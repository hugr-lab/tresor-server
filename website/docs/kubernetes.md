---
title: Kubernetes
---

# Kubernetes

The Helm chart deploys the service on any state store. With the Kubernetes store it needs nothing but the
cluster: no database, and with workload identity on AKS, no secret of its own.

```bash
helm install tresor oci://ghcr.io/hugr-lab/charts/tresor-server -n tresor --create-namespace -f values.yaml
```

Kubernetes 1.30 or later. The chart's own README lists every value.

## The Kubernetes store, the KEK in Key Vault (AKS)

```yaml
serviceAccount: {name: tresor}
workloadIdentity: {enabled: true, clientId: <the managed identity's client id>}
config:
  public_url: https://tresor.example.com
  state: {kind: kubernetes}
  keys: {kind: azurekeyvault, key: https://corp-kv.vault.azure.net/keys/tresor-kek}
  azure: {identity: workload}
  issuers:
    - {issuer: https://login.microsoftonline.com/<tenant>/v2.0, audience: <api client id>, roles_claim: roles}
  policy: {admins: [role:secrets_admin]}
ingress:
  enabled: true
  hosts: [{host: tresor.example.com}]
  tls: [{secretName: tresor-tls, hosts: [tresor.example.com]}]
```

On Azure:

- **The cluster** needs `--enable-oidc-issuer --enable-workload-identity`.
- **A user-assigned identity** with a federated credential: the cluster's issuer, subject
  `system:serviceaccount:<namespace>:<serviceAccount.name>`, audience `api://AzureADTokenExchange`.
- **Its rights on the KEK**: get, wrapKey, unwrapKey and sign, on the one key. No built-in role is exactly
  that, so use a custom role (see [Encryption](encryption.md)).
- **For `ref+azkv`**: *Key Vault Secrets User* on the secrets that references read.

The service stops at start when the pod has no identity injected, and names the label and the annotation to
set.

## The store

The store is custom resources in the release's namespace (see [State stores](state.md#kubernetes)):

- several replicas, compare-and-set through `resourceVersion`;
- a MAC over everything not sealed: a resource changed by hand is refused;
- the **admission policy** (cluster-scoped, in the chart): only the service's ServiceAccount writes. The
  garbage collector may delete minted tokens; the namespace controller deletes only while the namespace is
  being deleted. It stops the one thing the MAC does not: an older copy put back.

## The CRDs

- Helm installs `crds/` on the first install, whatever the store, and never upgrades them.
- On another store, or without cluster rights, install with `--skip-crds` and
  `admissionPolicy.enabled: false`.
- An upgrade that changes the CRDs says so: run `kubectl apply --server-side -f crds/` first.

## Kubernetes Secrets as material

```yaml
config:
  material:
    k8s:
      allow:
        - namespace: data-team
          prefixes: [duckdb-]
```

- A secret's parameter or a variable can name `ref+k8s://data-team/duckdb-lake/secret`
  (see [References](references.md)).
- The chart makes a Role per namespace listed, with `get` on Secrets.
- The service's own namespace is refused: its credentials are there.

## Other stores

- **PostgreSQL or SQL Server**: `config.state` as on any host.
  - The password can come from a Secret: `state.password_ref: ref+k8s://db/tresor-pg/password`. The chart
    grants `get` on that one Secret.
  - Or from workload identity, with `auth: entra`.
- **SQLite**: one replica on a PersistentVolumeClaim. Use block storage.

## Hardening

- With `tls.offload` the pod serves plain HTTP. Set `networkPolicy.from` to the ingress controller.
- Whoever can create pods in the service's namespace, mint a token for its ServiceAccount or impersonate it
  can act as the service. Keep these rights to the platform's operators.
- A restore (Velero) writes as another account. Remove the admission policy's binding for its duration.
