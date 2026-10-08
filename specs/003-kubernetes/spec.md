# Spec 003: phase 3 - Kubernetes

- **Status**: implemented
- **Date**: 2026-10-01
- **Author**: hugr lab

## Summary

Phase 3 of [spec 001](../001-architecture/spec.md): tresor-server on Kubernetes, with nothing but the
cluster.
- A **state store in the Kubernetes API**: custom resources in the service's namespace, compare-and-set
  through `resourceVersion`. Several replicas, no database.
- **Kubernetes Secrets as a material source**: `ref+k8s://<namespace>/<secret>/<key>`, within an
  allowlist. It also gives a database its password.
- **Workload identity**: on AKS, the pod's federated identity reaches Key Vault (the KEK, `ref+azkv`) and an
  Azure database. No secret of the service's own.
- **Integrity of what is not sealed**: on the Kubernetes store, a MAC under a data key over every field
  that is not sealed, and an admission policy that lets only the service write its resources.
- **A Helm chart**: the Deployment, the Service, an Ingress, a PodDisruptionBudget, the ServiceAccount and
  its RBAC, the CRDs, the admission policy. It deploys the service on any state store: the Kubernetes
  store, or SQL (PostgreSQL, SQL Server, SQLite).

No protocol change.

## Problem

Phase 1 runs on Container Apps and on any host with a database. A Kubernetes platform team wants:
- one artifact to install (a chart), the way they install everything else;
- no database to run for it, when the cluster already keeps state;
- credentials the platform already holds - Kubernetes Secrets, often synced from a vault by another tool -
  served to DuckDB without copying them into another store;
- the pod's identity, not a secret, for Key Vault and the cloud's databases.

## Design

### The state store: `state.kind: kubernetes`

Custom resources, group `tresor.hugr-lab.io`, version `v1alpha1`, all namespaced in the service's own
namespace. Everything is in `spec`; there is no status subresource.

| Kind | One per | Holds |
| --- | --- | --- |
| `TresorSecret` | secret | the name, the descriptor, the protocol's version, the grants, the sealed params |
| `TresorGrant` | delegation grant | the actor, the user, the expiry, the sealed subject token |
| `TresorMintedToken` | grant and audience | the sealed token or the refusal, its version |
| `TresorActor` | actor | how many live grants it holds: the per-actor limit's counter |
| `TresorDataKey` | data key | the wrapped data key, the KEK id |
| `TresorKeyring` | one, `active` | the active data key's id, its slot version |

**Compare-and-set** is the API server's:
- an update carries the `resourceVersion` it read; a `Conflict` runs `fn` again, as on the SQL stores;
- a create that finds the name taken (`AlreadyExists`) runs `fn` again too;
- a delete carries preconditions (the UID and the `resourceVersion` read): a secret changed or dropped
  and created again meanwhile is never deleted blind;
- errors are told apart by their reason (`IsConflict`, `IsAlreadyExists`), not by the status (both 409).

**Versions**:
- the protocol's `version` (the ETag) is a field of the spec, moved on every write;
- the `resourceVersion` is the store's own revision, and opaque.

**Names**:
- a resource is always named by a hash: a secret `s-<SHA-256 of its name, 40 hex>`, a grant
  `g-<SHA-256 of its id, 40 hex>`. A secret's own name is in its spec, checked on every read. Names that
  are no DNS subdomain (`Lake`, `a_b`) are fine; no name can take another's resource.
- the grant id itself is never stored.

**Grants in the `TresorSecret`**, not in sibling resources: a grant change and the secret's version move in
one update, compare-and-set, as `Update(fn)` wants. This settles spec 001's open question for grants.

**Delegation grants as resources of their own**, `TresorGrant`: they come and go with sessions and are
never part of a secret's write.
- Labels select them, each a SHA-256 in unpadded base32 (52 characters; a label value holds at most 63):
  `tresor.hugr-lab.io/actor-owner`, `/actor-client`, `/user`. `Count` and the limit use the first,
  revocation (`DeleteWhere`) the other two. A `TresorMintedToken` carries `/grant`.
- **Tokens go with their grant, by the store itself**: `Delete`, `DeleteWhere` and `Purge` delete the
  grant's tokens by their `/grant` label. The garbage collector is asynchronous (and absent from envtest):
  an owner reference to the grant is kept only as a backstop. `Token` and `PutToken` check that the grant
  is live first.
- **The per-actor limit**: a `TresorActor` counter, compare-and-set. A put reads it, counts the actor's live
  grants by label, creates the grant, then moves the counter on at the version read; on a conflict it
  deletes the grant it made and runs again. No lock, no clock. A replica that dies between the two leaves
  a grant no caller holds: it counts until it expires. The limit is never passed; under racing puts near
  it, one may be refused while another's grant, about to be deleted, still counts (the SQL stores' lock does
  not do that). A put runs at most 16 times.
- Expired grants and their tokens are purged every minute, as on the SQL stores.

**Data keys**: a data key is created first, then `TresorKeyring` is moved on compare-and-set on its slot
version (an int64 in the spec). A create of the keyring that finds it (`AlreadyExists`) is `ErrKeyRace`. A
data key orphaned by a lost race is harmless. `rewrap` updates a data key compare-and-set on its KEK id.

**Reads**:
- no informer cache: two replicas need each other's writes at once (the ETag). Every read goes to the API
  server, which reads etcd (or, on Kubernetes 1.31+, its consistent watch cache);
- a list is paged (`limit`, `continue`);
- `Ping` (readiness) lists one resource.

**Size**: a resource holds at most ~1.5 MiB in etcd, and base64 makes sealed bytes a third larger. A secret's
whole object - descriptor, grants, sealed params - is refused (`422`) over 256 KiB; a secret holds at most
1000 grants.

**The schema**: the CRDs are the chart's. At start the service checks, by API discovery (no cluster-scope
right needed), that its group serves the version it knows, every kind; otherwise it does not start. The
discovery is one GET, not client-go's discovery client: that one links every built-in API type (+25 MB).

**Material is never in a resource in the clear**: sealed, or a reference. Whoever can read the resources
still needs the KEK.

### Integrity of what is not sealed

On the Kubernetes store, a secret's descriptor and grants, and a delegation grant's actor and user, are
not sealed. Whoever can write the resources could make the service decrypt for them: a grant of `use` to
their own role, a forged delegation grant for an administrator. Write access to a namespace is easier to
get than write access to a database. Three guards.

#### A root only the KEK's holder can compute

An RSA KEK wraps with its **public** key: anyone who has it can make a data key that unwraps. A data key's
unwrapping proves nothing, and on every store a writer could plant one and seal material of their choice
under it. So the service derives a **root** from the KEK, which only the KEK's holder can compute:

| KEK | The root |
| --- | --- |
| Key Vault RSA | a deterministic signature (RS256, PKCS#1 v1.5) of a fixed label, made in the vault |
| Managed HSM AES | a deterministic wrap (A256KW) of a fixed label |
| local | HMAC-SHA256 of a fixed label under the local key |

- The root is per KEK version (the version is in the label), never stored, kept in memory for
  `keys.cache_ttl` with the data keys - one TTL: when the service loses its KEK rights, it stops within it.
- **Every data key is authenticated**, on every store: a tag, HMAC under the root, over its id, its KEK id,
  its creation time (to the microsecond) and its wrapped bytes. A data key whose tag does not match is
  refused (`ErrSealed`). This closes a planted data key on the SQL stores too. The creation time decides
  when a data key is replaced: in the tag, no writer of the store keeps one active for ever.
- **Tags from (a0)** (format 1, no creation time): the data key still opens, is never the active one (a new
  one is made), and `rewrap` tags it anew.
- **Keys from before**: no tag, refused until tagged. `tresor-server rewrap -tag-untagged` tags them once,
  at the upgrade, and logs each; a routine `rewrap` never tags a key with none (one planted since has none
  either).
- **The MAC key** (below) is derived from a **data key**: HMAC-SHA256 under the data key of a fixed label.
  The data key is authenticated by the root, so only the KEK's holder can make a MAC that verifies. A
  rotation of the KEK and a `rewrap` keep the data key, and so every MAC made under it: nothing is
  re-MACed. Each resource names its data key, in what the MAC covers.
- **The installation's id** (`state.instance`, default the namespace's name; kept stable, so a restore
  still verifies) is in every MAC: a resource moved from another installation that shares the KEK (dev and
  prod) does not verify.
- **The right it needs**: Key Vault `sign` on the KEK, beside get, wrapKey and unwrapKey. No built-in role
  gives exactly that (*Key Vault Crypto Service Encryption User* has no `sign`; *Key Vault Crypto User*
  gives encrypt and decrypt too): the recipes make a **custom role** with these four data actions, on the
  one key.

#### A MAC over every field that is not sealed

- HMAC-SHA256 under the MAC key of the data key the resource names, over a canonical encoding:
  - the format's version, the resource's kind and the installation's id first;
  - every field length-prefixed, every list count-prefixed in its order as stored (scope, redact keys,
    grants, verbs), absent and empty told apart, times as int64 nanoseconds;
  - a `TresorSecret`: its name, row id, type, provider, scope, redact keys, comment, owner, version,
    times, grants, data key id, sealed params;
  - a `TresorGrant`: its id hash, actor (owner, client, issuer), user, expiries, data key id, sealed
    subject token;
  - a `TresorMintedToken`: its grant, key, version, refusal, data key id, sealed token;
  - a `TresorActor`: its actor, counter and data key id.
- A resource with nothing sealed (a grant with no subject token, a refusal, a counter) is MACed under the
  active data key.
- **No MAC on the data keys and the keyring**: a data key is authenticated by its tag; the keyring only
  names one, and one planted is refused by its tag. A keyring changed to name another authentic data key:
  that key's age (in its tag) and KEK version decide whether it seals, as for any active key.
- **The installation's mark**: a `TresorKeyring` named `installation` holds the instance, MACed. Readiness
  (the `state` check) verifies it, and the first replica to look makes it. A wrong KEK or `state.instance`
  is not ready - not a service that lists nothing because every resource fails to verify.
- **What the MAC covers decides; the metadata is checked against it.** On every read the store recomputes
  the resource's name and labels from the MACed fields and refuses a mismatch (a relabelled grant would
  slip past revocation and the per-actor count). A resource with a `deletionTimestamp` is treated as gone
  (a secret: refused); one with a finalizer or an owner reference the service did not set is refused.
- **Checked before it is used**: on every read, and before `fn` runs in `Update` and before the actor's
  counter is moved - so a tampered resource is never re-MACed by the next honest write.
- **What a failure answers**:
  - a `Describe` or a `Get`: `500 service_error` (tresor spec 016) to an administrator, never a
    descriptor, never material; to anyone else the `404` of a missing secret - no one can be shown to hold
    a verb on it, and its existence does not leak (but during a KEK outage, `503` for a name that exists);
  - a list: the resource is left out, and logged - one bad resource never fails a list (spec 002); a
    delegation grant changed is not counted toward its actor's limit;
  - a delegation grant or a minted token: `500` where it is used, never honoured;
  - a KEK that does not answer while a check needs it: `503`, not 500.
- It does not stop a **rollback** - a whole older object put back, its MAC valid then: a revoked grant back
  again, a deleted secret back, an actor's counter back, a spent minted token back (which may make the IdP
  revoke the token's whole family). A delegation grant's expiry bounds it (8 hours at most). The admission
  policy is the guard; without it (`admissionPolicy.enabled: false`, or a stolen ServiceAccount token)
  there is none. The service cannot see the policy (that needs a cluster-scope right): the chart's notes
  warn when it is off.
- A hand edit (`kubectl edit`) makes the resource unreadable, as meant. A secret changed behind the store is
  refused to every request, a delete included (its grants cannot be trusted to say who may delete it): an
  operator deletes its resource by hand, past the admission policy.
- A revocation (`DeleteWhere`) and the purge delete what the labels select, a changed resource included: a
  delete gives no one anything.
- A backup restored (Velero; with the admission policy's binding removed for it) or a move with the same KEK and `state.instance` verifies. Minted tokens do
  not survive it: their owner references name the grants' old UIDs, and the garbage collector deletes them
  (they are minted again).
- The purge also sweeps minted tokens whose grant is gone (a stripped label or owner reference would
  leave them otherwise).

#### A ValidatingAdmissionPolicy (Kubernetes 1.30+), in the chart

- On `tresor.hugr-lab.io`, `resources: ["*/*"]` (every resource and subresource; the API server refuses `"*"` beside it), operations CREATE, UPDATE, DELETE,
  `matchPolicy: Equivalent`, `failurePolicy: Fail`, the binding's `validationActions: [Deny]`.
- Allowed: the service's ServiceAccount; for DELETE only, the garbage collector on minted tokens (the one kind
  with an owner reference) and the namespace controller while the namespace is being deleted
  (`namespaceObject.metadata.deletionTimestamp`) - or a namespace could not be deleted. A deletecollection
  is admitted as one DELETE per object. A wider exemption would let a holder of a controller's token delete
  the data keys: every sealed value lost.
- A restore (Velero) writes as another account: the binding is removed for its duration. Two releases in one
  namespace would lock each other out.
- It does not stop a cluster admin, who can remove it or delete the CRDs (which deletes every resource),
  nor a stolen ServiceAccount token: the MAC does, but for a rollback.
- It is cluster-scoped: installing it needs cluster rights; `admissionPolicy.enabled: false` for an older
  cluster, or an install with no such rights.

The SQL stores keep no MAC (writing a database is fewer people's; a setting later), but their data keys
are authenticated by the root.

### Kubernetes Secrets as a material source: `ref+k8s://`

`ref+k8s://<namespace>/<secret>/<key>`, a parameter's whole VARCHAR value.

- **Allowlist** (`material.k8s.allow`): namespaces, each with secret-name prefixes. Nothing else is read.
- **RBAC**: the chart gives the service `get` on Secrets only in the namespaces listed (a Role per
  namespace), nothing at cluster scope. A Role cannot match name prefixes: the prefixes are the allowlist's
  alone.
- **At a write and at each fetch**, the rules of `ref+azkv` (spec 002):
  - refused at the write when malformed or outside the allowlist (`422`);
  - read at each fetch, a failure `503`;
  - redacted;
  - logged with where and the Secret's observed `resourceVersion` (an opaque revision, not a content
    version), never the value.
- A Secret synced from a vault by another tool (External Secrets, the CSI driver) is served the same way:
  the rotation reaches DuckDB at its next fetch. An immutable Secret is rotated by a new name, which must
  match an allowed prefix.
- **A database password from a reference**: `state.password_ref: ref+k8s://…` (or `ref+azkv://…`), read for
  each new connection - spec 001's "a password comes from a MaterialSource".
  - It is read through a source of its own, whose allowlist is that one place.
  - It must be **outside every `material` allowlist** (the configuration is refused otherwise - checked by
    the configuration and by the sources' own parse): an administrator could otherwise write a secret that
    names it, and read the database's password. A copy synced into an allowlisted place is not caught.
  - It is parsed at start. RBAC: `get` on that one Secret, by `resourceNames`.
- **Never the service's own namespace** in `material.k8s.allow`: its own credentials are there (a local KEK,
  a password, a client secret). The service does not start if the allowlist names it.
- No cache: a read from the API server is cheap, and a rotation is seen at once.
- The source reads Secrets by the dynamic client: client-go's typed client links every built-in API type.

### Workload identity

- `azure.identity: workload`: `azidentity.WorkloadIdentityCredential`. The AKS webhook injects
  `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE` and `AZURE_AUTHORITY_HOST` into a pod
  labelled `azure.workload.identity/use: "true"`, whose ServiceAccount carries the
  `azure.workload.identity/client-id` annotation.
- Key Vault (the KEK, `ref+azkv`), Azure SQL and Azure Database for PostgreSQL then log in with no secret.
- `azure.client_id` overrides the webhook's `AZURE_CLIENT_ID`: that identity needs a federated credential for
  the ServiceAccount's subject and the cluster's issuer. A pod with no workload identity injected, or no
  token mounted, stops at start, naming the label and the annotation to set.
- On other clouds the same shape follows in phase 4 (AWS IRSA, GCP Workload Identity).
- The local KEK on Kubernetes: a Kubernetes Secret mounted as a file (`keys.key_file`) - a static secret, for
  clusters with no KMS.

### The Helm chart: `deploy/helm/tresor-server`

- **Any state store**, chosen in values:
  - `kubernetes` (default): no database; the CRDs, the admission policy;
  - `postgres`, `sqlserver`: a database outside the cluster, or in it. Logged in by workload identity
    (`auth: entra`) or a password from a Kubernetes Secret (`state.password_ref: ref+k8s://...`, read at
    each new connection); several replicas;
  - `sqlite`: one replica on a PersistentVolumeClaim.
- **Deployment**:
  - the image, `TRESOR_*` settings from values, probes on `/healthz` and `/readyz`;
  - non-root, a read-only root filesystem, an emptyDir `/tmp`;
  - several replicas (2 by default) on `kubernetes`, `postgres`, `sqlserver`;
  - one on `sqlite`: a PersistentVolumeClaim at the data directory (the database, its WAL and shared
    memory), `fsGroup`, `strategy: Recreate`.
- **Service**, and an optional **Ingress** (TLS at the ingress controller: `tls.offload`), or a TLS secret
  for the pod itself.
- **PodDisruptionBudget** (`minAvailable: 1`) with several replicas.
- **ServiceAccount**, with the workload identity's annotation; the pod template with its label.
- **RBAC**:
  - a Role in the service's namespace on its custom resources (get, list, watch, create, update, delete,
    deletecollection);
  - a Role per namespace of `material.k8s.allow`, `get` on Secrets. Installing it needs rights in those
    namespaces.
- **CRDs** in the chart's `crds/`: installed once, never deleted with a release - and never upgraded by
  Helm. An upgrade that changes them says so: `kubectl apply --server-side -f crds/` first.
- **The admission policy** and its binding, with the Kubernetes store (`admissionPolicy.enabled`).
- **values.yaml**: the issuers, the policy, the state, the keys, the material - typed as the service's
  configuration.
- Published as an OCI chart, `oci://ghcr.io/hugr-lab/charts/tresor-server`, from a tag (`vX.Y.Z`: chart
  `X.Y.Z`, the image `vX.Y.Z`).
- **At (d)**:
  - `values.config` is the service's `server.yaml` as it is. The chart derives the RBAC, the volumes, the
    admission policy and the CRDs' use from it, and fails a render whose `material.k8s.allow` names the
    release's namespace.
  - A `preStop` sleep (the kubelet's own: the image has no shell): the endpoints drop the pod before it
    stops serving.
  - The policy also lets `system:kube-controller-manager` delete, in the same two cases: a controller manager
    that runs without per-controller credentials.
  - A render the service would refuse fails (no issuer, no KEK, a SQLite path off the volume, the namespace's
    default ServiceAccount, the release's namespace in `material.k8s.allow`); `memory` runs one replica.
  - An optional NetworkPolicy: with `tls.offload` only the ingress controller should reach the plain HTTP.
  - CI on kind:
    - a CA of the run's, an OIDC issuer (nginx, static discovery and JWKS), PostgreSQL with TLS;
    - two installs, each checked through the protocol (`scripts/ci/kind.sh`);
    - the policy checked by server dry runs: a hand write, a delete, a rollback (an UPDATE) and a
      controller's delete outside its case are denied; the namespace's deletion completes;
    - `ref+k8s` from another namespace, and a delete, through the protocol.

### Configuration

```yaml
state:
  kind: kubernetes
  namespace: tresor            # in a pod: the pod's own by default; outside one (KUBECONFIG): required
  password_ref: ""             # postgres/sqlserver: ref+k8s:// or ref+azkv:// for auth: password
material:
  k8s:
    allow:
      - namespace: data-team
        prefixes: [duckdb-]
azure:
  identity: workload           # managed | workload | default
```

The service reaches the API in-cluster (its ServiceAccount), or through `KUBECONFIG` outside a pod (tests,
development).

### CI

- **The StateStore suite on the Kubernetes store**, against a real API server: envtest (controller-runtime's
  kube-apiserver and etcd binaries from `setup-envtest`, no cluster), the CRDs installed. Two store handles
  as two replicas. envtest has no garbage collector: the store's own deletes are what the suite checks.
- **Conformance on the Kubernetes store**: a small Go helper starts envtest, writes a kubeconfig, and runs
  two replicas of the service behind the proxy - through tresor's `TRESOR_SERVER_CMD`, as today.
- **The chart**: `helm lint`; `helm template` checked with kubeconform; an install into `kind` (the image
  loaded with `kind load docker-image`, a local KEK Secret) until `/readyz` answers.
- **`ref+k8s`**: the API test with a fake source; the envtest suite with a real Secret.

### The PRs

1. **(a0) the root** (landed): the KEK's `Derive` (RSA sign, AES wrap, local HMAC), data keys authenticated on
   every store, `keys.cache_ttl` for all; the custom role in the Container Apps recipe.
2. **(a) the Kubernetes store** (landed): the CRDs, `state.kind: kubernetes`, the MAC, the suite on envtest,
   conformance on it.
3. **(b) `ref+k8s://`** (landed): the source, its allowlist, `state.password_ref`.
4. **(c) workload identity** (landed): `azure.identity: workload`.
5. **(d) the Helm chart** (landed): every state store, the admission policy; lint, template, kind installs in CI
   (the Kubernetes store, and PostgreSQL in the cluster); the OCI chart from a tag.
6. **(e) docs and the live run** (landed): a Kubernetes page on the site; AKS with the Kubernetes store, Key Vault
   by workload identity, the chart.

## Enforcement & security

- **Fail closed**, as on every store:
  - an API server that does not answer is `503`;
  - a resource whose sealed params do not open fails that read;
  - a group that does not serve the version the service knows stops it.
- **Least privilege**:
  - the service reads and writes only its own namespace's custom resources;
  - it reads Secrets only in the allowlisted namespaces, by RBAC and by the allowlist;
  - nothing at cluster scope.
- **etcd at rest**: the resources hold only sealed values and hashes. Kubernetes' encryption at rest adds
  to it; it is not relied on.
- **What is not sealed is checked**: the MAC makes a forged or changed resource need the KEK; the admission
  policy keeps everyone but the service from writing at all. Left: a rollback to a whole older object
  (bounded for delegation grants by their expiry), by a cluster admin or with the service's own token.
- **The namespace**: the service runs in one of its own. The right to create pods there (a pod could run
  as its ServiceAccount) goes to the platform's operators only. The chart's README says so.
- **No static secret** with workload identity; a local KEK in a Kubernetes Secret only where there is no
  KMS.

## Testing

- The StateStore suite on envtest (CI), as on the SQL stores. The Kubernetes-only cases:
  - a resource changed behind the store (a grant added, a user changed, a label changed, a finalizer
    added): refused; an older object put back: recorded as passing (the policy is the guard);
  - a data key planted with the RSA public key: refused, on every store;
  - a resource moved from another installation: refused;
  - a list with one tampered resource: the others listed;
  - a name that is no DNS subdomain;
  - the size and grant limits;
  - a delete that finds the secret changed (its preconditions);
  - tokens deleted with their grant by the store, with no garbage collector;
  - the label selectors, the `TresorActor` counter under racing puts.
- tresor's conformance suite on the Kubernetes store, two replicas.
- `ref+k8s` against a real Secret on envtest.
- The chart on kind in CI: the Kubernetes store, the admission policy refusing a hand write and letting the
  garbage collector delete; PostgreSQL in the cluster, its password by `ref+k8s`.
- Live, by hand: AKS with the Kubernetes store, Key Vault by workload identity, the chart from ghcr.io.

## Alternatives considered

- **Delegation grants in the `TresorSecret`'s status, or one resource for all.** A grant is not part of
  any secret; one shared resource would serialize every session on one `resourceVersion` and grow without
  bound.
- **Grants as sibling resources** (`TresorSecretGrant`). A grant change must move the secret's version in
  the same compare-and-set; two resources would need a transaction the API server does not have.
- **A coordination Lease as the per-actor lock.** No fencing (a paused holder past its expiry lets two
  replicas pass the limit), two or three more calls per exchange, Leases left behind. The counter needs
  none of it.
- **The garbage collector alone** for a grant's tokens. Asynchronous, and not in envtest.
- **An informer cache.** A replica would serve another's write late: the ETag would go back in time.
- **A ConfigMap per secret** instead of a CRD. No schema, no clean RBAC by kind, mixed with everything
  else in the namespace.
- **controller-runtime as the client.** A controller's machinery the service does not need: the store
  talks to the API with client-go's dynamic client and its own types; envtest is for tests only.
- **An operator** reconciling `TresorSecret` resources written by users (GitOps). Writes go through the
  protocol, by administrators, with the protocol's checks; a resource applied by hand would skip them.
  Possible later, as its own spec.

## Decisions (2026-10-01)

- **The API group**: `tresor.hugr-lab.io`.
- **Integrity**: the MAC and the admission policy, both, on the Kubernetes store; no MAC on the SQL stores
  for now.
- **After the review of the MAC**: a root only the KEK's holder computes; data keys authenticated by it on
  every store; the KEK needs `sign` (a custom role: get, wrapKey, unwrapKey, sign) - the Container Apps
  recipe changes with it.
- **The live run**: AKS with the Kubernetes store only.
- **The chart**: in this repository, `deploy/helm/tresor-server`, published to
  `oci://ghcr.io/hugr-lab/charts`. It deploys the service on any state store, SQL included.

- **At (a), the MAC key from the data key**, not the root: a KEK rotation and its `rewrap` would otherwise
  have to re-MAC every resource before the old KEK version is retired.

- **The live run (2026-10-01)**: `scripts/dev/aks_live.sh` on AKS 1.35 in westeurope:
  - one `Standard_D2s_v6` node (the subscription has no `Bsv2` quota there);
  - the chart from this repository, with the image `edge`, on the Kubernetes store with two replicas;
  - the KEK an RSA key in Key Vault, reached by workload identity with no secret of the service's own:
    a federated credential, and the custom role (get, wrap, unwrap, sign) on the one key;
  - `ref+azkv` in a secret and in a variable (spec 004);
  - the admission policy on.
  Readiness was `ok` for the state, the keys and the issuer. Through the protocol, with the in-cluster issuer
  of `scripts/ci/incluster.sh`, a secret and a variable were written, granted, read and deleted, and both
  references resolved, the variable as `sensitive`. A hand delete was refused, and no value reached the log.
  Everything was deleted afterwards (the group, the custom role, the vault purged, and the NetworkWatcherRG AKS
  made).

## Follow-ups

- An operator for GitOps (resources applied by hand, checked as the protocol checks a write).
- AWS IRSA and GCP Workload Identity (phase 4).
- The MAC on the SQL stores, as a setting.
- Metrics: a count of the resources a list left out. Done: `tresor.state.left_out` (spec 005).
- `TresorActor` counters are never deleted: one per actor ever seen. Done (2026-10-08): the purge reads the
  counters, then the grants, and deletes the counter of an actor with no live grant, compare-and-set on the
  version read first: a put that moved it since keeps it, one that moves it after finds it gone and runs again,
  and a counter created since the read is never deleted - so a put from no counter cannot pass the limit.
