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
  `listen`, and with SQLite `state.path`. It derives the rest from `config`:
  - `state.kind: kubernetes` brings in the CRDs, a Role on them, and the admission policy;
  - `material.k8s.allow` gets a Role per namespace (`get` on Secrets);
  - `state.password_ref: ref+k8s://…` gets a Role on that one Secret, by name.
- `localKEK.secretName`: a local KEK from a Secret (32 bytes, base64), mounted for `keys.key_file`.
- `workloadIdentity`: AKS workload identity (`azure.identity: workload`), with the pod's label and the
  ServiceAccount's annotation.
- `tlsSecret`: TLS in the pod itself. Otherwise `tls.offload`, with TLS at the ingress.
- `env`, `extraVolumes`: a client secret (`exchange.client_secret_env`), a private CA (`SSL_CERT_FILE`),
  `TRESOR_*` settings.
- `replicas`: 2 by default. SQLite always runs one, on a PersistentVolumeClaim, with `strategy: Recreate`.

## On the Kubernetes store

- **The CRDs** are in `crds/`. Helm installs them once and never upgrades or deletes them. An upgrade that
  changes them says so: run `kubectl apply --server-side -f crds/` first.
- **The admission policy** is cluster-scoped, so installing it needs cluster rights. It lets only the
  service's ServiceAccount write the resources, and lets the garbage collector and the namespace controller
  delete them.
  - `admissionPolicy.enabled: false` turns it off, for an older cluster or an install without cluster rights.
  - Without it, a hand edit is still refused by the MAC, but a rollback is not.
- **One installation per namespace.** Keep `config.state.instance` stable (the namespace by default), so a
  backup restored with the same KEK verifies.

## The namespace

- Whoever can create pods in the service's namespace can run as its ServiceAccount, so they can read its
  resources and its Secrets. Keep that right to the platform's operators.
- `material.k8s.allow` may not name this namespace: the service's own credentials are there.
