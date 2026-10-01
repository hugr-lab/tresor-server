# Spec 003: phase 3 - Kubernetes

- **Status**: draft
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
- **A Helm chart**: the Deployment, the Service, an Ingress, a PodDisruptionBudget, the ServiceAccount and
  its RBAC, the CRDs.

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
  deletes the grant it made and runs again. No lock, no clock.
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
right needed), that its group serves the version it knows; otherwise it does not start.

**Material is never in a resource in the clear**: sealed, or a reference. Whoever can read the resources
still needs the KEK.

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

### Workload identity

- `azure.identity: workload`: `azidentity.WorkloadIdentityCredential`. The AKS webhook injects
  `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE` and `AZURE_AUTHORITY_HOST` into a pod
  labelled `azure.workload.identity/use: "true"`, whose ServiceAccount carries the
  `azure.workload.identity/client-id` annotation.
- Key Vault (the KEK, `ref+azkv`), Azure SQL and Azure Database for PostgreSQL then log in with no secret.
- On other clouds the same shape follows in phase 4 (AWS IRSA, GCP Workload Identity).
- The local KEK on Kubernetes: a Kubernetes Secret mounted as a file (`keys.key_file`) - a static secret, for
  clusters with no KMS.

### The Helm chart: `deploy/helm/tresor-server`

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
- **values.yaml**: the issuers, the policy, the state, the keys, the material - typed as the service's
  configuration.
- Published as an OCI chart, `oci://ghcr.io/hugr-lab/charts/tresor-server`, from a tag.

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

1. **(a) the Kubernetes store**: the CRDs, `state.kind: kubernetes`, the suite on envtest, conformance on
   it.
2. **(b) `ref+k8s://`**: the source, its allowlist, `state.password_ref`.
3. **(c) workload identity**: `azure.identity: workload`.
4. **(d) the Helm chart**: lint, template, kind install in CI; the OCI chart from a tag.
5. **(e) docs**: a Kubernetes page on the site; a live run on AKS, if the owner wants one.

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
- **Who can write the resources is trusted**, as whoever can write the database. A secret's grants and a
  delegation grant's user and actor are not sealed: writing them can give anyone `use`, or forge a grant.
  - The service runs in a namespace of its own. Write access to its resources, and the right to create
    pods there (a pod could run as its ServiceAccount), go to the service and the platform's operators
    only. The chart's README says so.
  - A MAC over the unsealed fields, under the data key, would make a forgery need the KEK (see the open
    questions).
- **No static secret** with workload identity; a local KEK in a Kubernetes Secret only where there is no
  KMS.

## Testing

- The StateStore suite on envtest (CI), as on the SQL stores. The Kubernetes-only cases:
  - a name that is no DNS subdomain;
  - the size and grant limits;
  - a delete that finds the secret changed (its preconditions);
  - tokens deleted with their grant by the store, with no garbage collector;
  - the label selectors, the `TresorActor` counter under racing puts.
- tresor's conformance suite on the Kubernetes store, two replicas.
- `ref+k8s` against a real Secret on envtest.
- The chart on kind in CI.
- Live, by hand, if the owner wants it: AKS with workload identity, Key Vault, the chart.

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

## Open questions

- **The API group**: `tresor.hugr-lab.io`?
- **A MAC over the unsealed fields** (a secret's descriptor and grants, a delegation grant's user and
  actor), under the data key: a forgery would need the KEK. The price: with the KEK down, past the data
  keys' 5-minute cache, descriptors stop answering too. Now, for the Kubernetes store only, for every
  store, or later?
- **A live run on AKS**: wanted, and with which store - the Kubernetes store alone, or also PostgreSQL /
  Azure SQL through workload identity?
- **The chart's home**: this repository (`deploy/helm/tresor-server`), published to
  `oci://ghcr.io/hugr-lab/charts`?

## Follow-ups

- An operator for GitOps (resources applied by hand, checked as the protocol checks a write).
- AWS IRSA and GCP Workload Identity (phase 4).
