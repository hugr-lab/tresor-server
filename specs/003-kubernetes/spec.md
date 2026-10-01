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
  allowlist.
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
namespace:

| Kind | One per | Holds |
| --- | --- | --- |
| `TresorSecret` | secret | the descriptor, the grants, the sealed params (data key id, row id) |
| `TresorGrant` | delegation grant | the actor, the user, the expiry, the sealed subject token |
| `TresorMintedToken` | grant and audience | the sealed token, the refusal; owned by its `TresorGrant` |
| `TresorDataKey` | data key | the wrapped data key, the KEK id |
| `TresorKeyring` | one, `active` | the active data key's id |

- **Compare-and-set** is the API server's: an update carries the `resourceVersion` it read; a conflict
  (409) runs `fn` again, as on the SQL stores. A create that finds the name taken is a conflict too.
- **The protocol's `version`** stays a field of the spec, as in the SQL stores: it moves on every write; the
  `resourceVersion` is the store's own revision.
- **Grants in the `TresorSecret`** (not sibling resources): a grant change and the secret's version move
  in one update, compare-and-set, as `Update(fn)` wants. This settles spec 001's open question for grants.
- **Delegation grants as resources of their own** (`TresorGrant`): they come and go with sessions, and
  are never part of a secret's write.
  - The name is the grant id's SHA-256 (hex): the id itself is never stored.
  - A minted token is a `TresorMintedToken`, its owner reference the grant: deleting the grant deletes
    its tokens (the garbage collector).
  - Revocation by actor or user is a label selector: `tresor.hugr-lab.io/actor` and `/user` labels hold
    a SHA-256 of the principal (a label value cannot hold `|` or `:`).
  - The per-actor limit is counted by the label, under a `coordination.k8s.io` Lease per actor (a lock with
    a short expiry), so racing replicas cannot pass it.
  - Expired grants are purged every minute, as on the SQL stores.
- **Names**: a resource's name is a DNS subdomain. A secret's name that is not one (`Lake`, `a_b`) is kept
  in the spec; the resource is named `s-<SHA-256 of the name, 40 hex>`. Lookups by name read that
  resource; listing reads them all.
- **Size**: a resource holds at most ~1 MiB (etcd). A secret's sealed params are small; the service
  refuses (`422`) a secret over 256 KiB sealed.
- **No migrations**: the CRDs' schema is the chart's. A version of the service checks that the CRDs it
  finds are the ones it knows (a label on the CRD with its schema version), or refuses to start.
- **Material is never in a resource in the clear**: sealed, or a reference. Whoever can read the
  resources still needs the KEK.

### Kubernetes Secrets as a material source: `ref+k8s://`

`ref+k8s://<namespace>/<secret>/<key>`, a parameter's whole VARCHAR value.

- **Allowlist** (`material.k8s.allow`): namespaces, each with secret-name prefixes. Nothing else is read.
- **RBAC**: the chart gives the service `get` on Secrets only in the namespaces listed (a Role per
  namespace), and nothing at cluster scope. The allowlist and the RBAC agree; either alone refuses.
- **At a write and at each fetch** the same rules as `ref+azkv` (spec 002): refused at the write when
  malformed or outside the allowlist (`422`); read at each fetch, a failure is `503`; redacted; logged
  with where and which `resourceVersion`, never the value.
- A Secret synced from a vault by another tool (External Secrets, the CSI driver) is served the same way:
  the rotation reaches DuckDB at its next fetch.

### Workload identity

- `azure.identity: workload`: the AKS workload identity (`azidentity.WorkloadIdentityCredential` - the
  federated token the pod's ServiceAccount projects). Key Vault (the KEK, `ref+azkv`), Azure SQL and Azure
  Database for PostgreSQL then log in with no secret.
- On other clouds the same shape follows in phase 4 (AWS IRSA, GCP Workload Identity).
- The local KEK on Kubernetes: a Kubernetes Secret mounted as a file (`keys.key_file`) - a static secret,
  for clusters with no KMS.

### The Helm chart: `deploy/helm/tresor-server`

- **Deployment**: the image, `TRESOR_*` settings from values, probes on `/healthz` and `/readyz`, a
  non-root read-only root filesystem, resources; several replicas (2 by default) on `kubernetes`,
  `postgres`, `sqlserver`; one on `sqlite` (a PersistentVolumeClaim, `strategy: Recreate`).
- **Service**, and an optional **Ingress** (TLS at the ingress controller: `tls.offload`) or a TLS
  secret for the pod itself.
- **PodDisruptionBudget** (`minAvailable: 1`) when there are several replicas.
- **ServiceAccount**, with the workload identity's annotation and label when configured.
- **RBAC**:
  - a Role in the service's namespace on its custom resources (get, list, watch, create, update, delete),
    and on Leases (the per-actor lock);
  - a Role per namespace of `material.k8s.allow` with `get` on Secrets.
- **CRDs** in the chart's `crds/` (installed once, never deleted with a release).
- **values.yaml**: the issuers, the policy, the state, the keys, the material - the configuration, typed
  as the service's.
- Published as an OCI chart: `oci://ghcr.io/hugr-lab/charts/tresor-server`, from a tag.

### Configuration

```yaml
state:
  kind: kubernetes             # in-cluster config; the service's namespace from the pod
  namespace: ""                # default: the pod's own (POD_NAMESPACE / the service account's)
material:
  k8s:
    allow:
      - namespace: data-team
        prefixes: [duckdb-]
azure:
  identity: workload           # managed | workload | default
```

### CI

- **The StateStore suite on the Kubernetes store**, against a real API server: `envtest`
  (controller-runtime's kube-apiserver and etcd binaries, no cluster), with the CRDs installed. Two store
  handles as two replicas.
- **Conformance on the Kubernetes store**: the service outside the cluster, pointed at envtest's API
  server (a kubeconfig), two replicas behind the proxy - through tresor's `TRESOR_SERVER_CMD` as today.
- **The chart**: `helm lint`, `helm template` against a schema check (kubeconform), and an install into a
  `kind` cluster with the service ready (`/readyz`).
- **`ref+k8s`**: the API test with a fake source; the envtest suite with a real Secret.

### The PRs

1. **(a) the Kubernetes store**: the CRDs, `state.kind: kubernetes`, the suite on envtest, conformance on
   it.
2. **(b) `ref+k8s://`**: the source, its allowlist, its tests.
3. **(c) workload identity**: `azure.identity: workload`.
4. **(d) the Helm chart**: lint, template, kind install in CI; the OCI chart from a tag.
5. **(e) docs**: a Kubernetes page on the site; a live run on AKS, if the owner wants one.

## Enforcement & security

- **Fail closed**, as on every store: an API server that does not answer is `503`; a resource whose
  sealed params do not open fails that read; CRDs of an unknown schema version stop the service.
- **Least privilege**: the service reads and writes only its own namespace's custom resources; it reads
  Secrets only in the allowlisted namespaces, by RBAC and by the allowlist. Nothing at cluster scope but
  what the chart's CRDs need at install.
- **etcd at rest**: the resources hold only sealed values and hashes. Kubernetes' own encryption at rest
  adds to it, it is not relied on.
- **Who can write the resources is trusted**, as whoever can write the database: a grant in a
  `TresorSecret` is not sealed. The namespace's RBAC must give that write to the service alone.
- **No static secret** with workload identity; a local KEK in a Kubernetes Secret only where there is no
  KMS.

## Testing

- The StateStore suite on envtest (CI), as on the SQL stores; the Kubernetes-only cases: a name that is not
  a DNS subdomain, the size limit, the owner-reference cascade, the label selectors, the per-actor Lease.
- tresor's conformance suite on the Kubernetes store, two replicas.
- `ref+k8s` against a real Secret on envtest.
- The chart on kind in CI.
- Live, by hand, if the owner wants it: AKS with workload identity, Key Vault, the chart.

## Alternatives considered

- **Delegation grants in the `TresorSecret`'s status, or in one resource for all.** A grant is not part of
  any secret; one shared resource would serialize every session on one `resourceVersion` and grow without
  bound.
- **Grants as sibling resources** (`TresorSecretGrant`). A grant change must move the secret's version in
  the same compare-and-set; two resources would need a transaction the API server does not have.
- **A ConfigMap per secret** instead of a CRD. No schema, no clean RBAC by kind, mixed with everything else
  in the namespace.
- **controller-runtime as the client.** A controller's machinery the service does not need. The store
  talks to the API with client-go's dynamic client and its own types; envtest is used for tests only.
- **An operator** reconciling `TresorSecret` resources written by users (GitOps). Writes go through the
  protocol, by administrators, with the protocol's checks; a resource applied by hand would skip them.
  Possible later, as its own spec.

## Open questions

- **The API group**: `tresor.hugr-lab.io`?
- **A live run on AKS**: wanted, and with which database - the Kubernetes store alone, or also PostgreSQL /
  Azure SQL through workload identity?
- **The chart's home**: in this repository (`deploy/helm/tresor-server`), published to
  `oci://ghcr.io/hugr-lab/charts`?

## Follow-ups

- An operator for GitOps (resources applied by hand, checked as the protocol checks a write).
- AWS IRSA and GCP Workload Identity (phase 4).
