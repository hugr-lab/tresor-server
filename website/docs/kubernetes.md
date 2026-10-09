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
  className: nginx            # unless the cluster has a default class
  hosts: [{host: tresor.example.com}]
  tls: [{secretName: tresor-tls, hosts: [tresor.example.com]}]   # cert-manager, or a TLS Secret of yours
```

On Azure:

- **The cluster** needs `--enable-oidc-issuer --enable-workload-identity`.
- **The KEK**: an RSA key with the operations wrapKey, unwrapKey and **sign** (sign makes the root, see
  [Encryption](encryption.md)).
- **A user-assigned identity**, federated with the release's ServiceAccount:

  ```bash
  az identity create -g <rg> -n tresor
  az identity federated-credential create -g <rg> --identity-name tresor -n tresor-sa \
    --issuer "$(az aks show -g <rg> -n <cluster> --query oidcIssuerProfile.issuerUrl -o tsv)" \
    --subject system:serviceaccount:<namespace>:<serviceAccount.name> --audiences api://AzureADTokenExchange
  ```

- **Its rights on the KEK**: get, wrap, unwrap and sign, on the one key. No built-in role gives exactly
  that, so make a custom role:

  ```bash
  az role definition create --role-definition '{
    "Name": "tresor KEK user", "Actions": [],
    "DataActions": ["Microsoft.KeyVault/vaults/keys/read", "Microsoft.KeyVault/vaults/keys/wrap/action",
                    "Microsoft.KeyVault/vaults/keys/unwrap/action", "Microsoft.KeyVault/vaults/keys/sign/action"],
    "AssignableScopes": ["/subscriptions/<subscription>/resourceGroups/<rg>"]}'
  az role assignment create --assignee-object-id <the identity's principal id> --assignee-principal-type ServicePrincipal \
    --role "tresor KEK user" --scope "<the vault's id>/keys/<key>"
  ```

- **For `ref+azkv`**: `config.material.azkv.allow` names the vault and the secret-name prefixes. The identity
  needs *Key Vault Secrets User* on those secrets.
- **A private CA**, such as an IdP's: mount it and set `SSL_CERT_DIR` to its directory. That adds it to the
  system's roots. `SSL_CERT_FILE` would replace them, and Key Vault's TLS would fail.

`scripts/dev/aks_live.sh` does all of this for a live check.

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
- **On another store**, install with `--skip-crds`.
- **On the Kubernetes store without cluster rights**: a cluster admin applies `crds/` first. Install with
  `--skip-crds` and `admissionPolicy.enabled: false` (the policy is cluster-scoped too).
- **An upgrade** that changes the CRDs says so: run `kubectl apply --server-side -f crds/` first. Variables
  (spec 004) brought `TresorVariable`: an install from before needs it, or the service does not start.
- **One installation per namespace**: a second release's admission policy would lock the first out.

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

## OpenBao or Vault

The KEK in Transit, `ref+vault` and the exchange's key in Vault, with the chart's `vaultToken`: see
[OpenBao and Vault](vault.md).

## Other stores

- **PostgreSQL or SQL Server**: `config.state` as on any host.
  - The password can come from a Secret: `state.password_ref: ref+k8s://db/tresor-pg/password`. The chart
    grants `get` on that one Secret.
  - Or from workload identity, with `auth: entra`.
- **SQLite**: not recommended on a cluster - one replica on a ReadWriteOnce claim, and the commands that write
  (`mac`, `reseal`) need the service scaled to 0 first. A cluster can run PostgreSQL or SQL Server: use one.

## The commands as jobs

The image has no shell, and nobody logs into the pod. Each command runs as a Job with the service's own
ServiceAccount, configuration, volumes and environment (spec 019). The chart makes a suspended CronJob per
command; start one by hand:

```sh
kubectl -n tresor create job --from=cronjob/<release>-tresor-server-reseal reseal-$(date +%Y%m%d%H%M)
kubectl -n tresor logs -f job/reseal-…        # its log: counts and names, never a value
```

| CronJob | Runs |
| --- | --- |
| `<release>-tresor-server-reseal` | `reseal -retire` |
| `<release>-tresor-server-reseal-rotate` | `reseal -rotate -retire` (a data key leaked) |
| `<release>-tresor-server-rewrap` | `rewrap` |
| `<release>-tresor-server-refs` | `refs -resolve` |
| `<release>-tresor-server-mac` | `mac` (the SQL stores) |

- `maintenance.reseal.schedule` (a cron, e.g. `0 3 1 * *`) runs `reseal -retire` on that schedule.
- `maintenance.refsBeforeUpgrade: true` runs `refs -resolve` with the new configuration before each upgrade (a
  pre-upgrade hook): a reference it would strand stops the upgrade.
- The right to create Jobs in the namespace is the KEK's: whoever has it acts as the service.

## Hardening

- With `tls.offload` the pod serves plain HTTP. Set `networkPolicy.from` to the ingress controller.
- Whoever can create pods or Jobs in the service's namespace, mint a token for its ServiceAccount or impersonate it
  can act as the service. Keep these rights to the platform's operators.
- A restore (Velero) writes as another account. Remove the admission policy's binding for its duration.
