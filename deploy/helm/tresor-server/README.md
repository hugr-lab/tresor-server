# tresor-server Helm chart

The `duckdb-secrets/1` service behind [tresor](https://github.com/hugr-lab/tresor), on any state store:
Kubernetes (custom resources, no database), PostgreSQL, SQL Server, SQLite. See
[the docs](https://hugr-lab.github.io/tresor-server/) and spec 003.

```bash
helm install tresor oci://ghcr.io/hugr-lab/charts/tresor-server -n tresor --create-namespace -f values.yaml
```

Kubernetes 1.30 or later.

## Values

- `config` is the service's own configuration (its `server.yaml`), as documented on the site. The chart sets
  `listen`, and when unset `tls` (offload), `keys` (local, from `localKEK`) and with SQLite `state.path`. A
  render that the service would refuse fails: no issuer, no KEK, a path off the volume. It derives the rest
  from `config`:
  - `state.kind: kubernetes` brings in the CRDs, a Role on them, and the admission policy;
  - `material.k8s.allow` gets a Role per namespace (`get` on Secrets);
  - `state.password_ref: ref+k8s://…` gets a Role on that one Secret, by name.
- `localKEK.secretName`: a local KEK from a Secret (32 bytes, base64), mounted for `keys.key_file`.
- `workloadIdentity`: AKS workload identity (`azure.identity: workload`), with the pod's label and the
  ServiceAccount's annotation.
- `tlsSecret`: TLS in the pod itself. Otherwise `tls.offload`, with TLS at the ingress.
- `env`, `extraVolumes`: a client secret (`exchange.client_secret_env`), a private CA (`SSL_CERT_DIR`, which
  adds to the system's roots; `SSL_CERT_FILE` would replace them, and Key Vault's TLS with them). Not
  `TRESOR_*` settings: the RBAC and the volumes are derived from `config`, which they would override.
- `replicas`: 2 by default. SQLite and memory always run one; SQLite on a PersistentVolumeClaim, with
  `strategy: Recreate`. Give SQLite block storage: a WAL on Azure Files or NFS is not safe.
- `rbac.secrets: false`: the Roles on Secrets (`material.k8s.allow`, `state.password_ref`) are yours to make.
- `networkPolicy`: with `tls.offload` the pod serves plain HTTP - bearer tokens on the pod network. Let only
  the ingress controller reach it (`networkPolicy.from`).

## On the Kubernetes store

- **The CRDs** are in `crds/`. Helm installs them on every first install, whatever the store, and never
  upgrades or deletes them. On another store, or without cluster rights, install with `--skip-crds`. An
  upgrade that changes them says so: run `kubectl apply --server-side -f crds/` first. Variables (spec 004)
  brought `TresorVariable`: an install from before needs it applied, or the service does not start.
- **The admission policy** is cluster-scoped, so installing it needs cluster rights. It lets only the
  service's ServiceAccount write the resources. The garbage collector may delete minted tokens (the one
  kind with an owner); the namespace controller may delete only while the namespace is being deleted.
  - `admissionPolicy.enabled: false` turns it off, for an older cluster or an install without cluster rights.
  - Without it, a hand edit is still refused by the MAC, but a rollback is not.
- **One installation per namespace.** A second release's policy admits only its own ServiceAccount: the two
  would lock each other out. Keep `config.state.instance` stable (the namespace by default), so a backup
  restored with the same KEK verifies.
- **A restore** (Velero) writes the resources as another account: remove the policy's binding for its
  duration.

## The namespace

- Whoever can create pods in the service's namespace, create a token for its ServiceAccount
  (`serviceaccounts/token`) or impersonate it can act as the service: read its resources and its Secrets,
  and write past the policy. Keep these rights to the platform's operators.
- `material.k8s.allow` may not name this namespace: the service's own credentials are there.
