---
title: Changing the configuration
---

# Changing the configuration

**When**: a setting changes - an issuer, the policy, an allowlist, a source, the KEK, the store's login.

**Who**: the platform operator.

The configuration is read at start only. A change takes effect when the replicas restart with it. Every setting
is in [Configuration](../configuration.md).

## Steps

### 1. Check the references with the new configuration

A source renamed or removed, or an allowlist narrowed, strands references silently: they fail at their next fetch.
`refs` lists them before they do ([Operations](../operations.md#checking-references)).

- **Kubernetes, the chart**: `maintenance.refsBeforeUpgrade: true` runs `refs -resolve` with the new
  configuration as a pre-upgrade hook. A finding (exit 3) or an error stops the upgrade:

  ```sh
  kubectl -n tresor logs job/<fullname>-refs-before-upgrade
  ```

  It runs only when the image stays (a configuration change), with Helm only (not `helm template`, not Argo CD),
  not on SQLite, and with the release's current ServiceAccount and RBAC. Change the image, the ServiceAccount or the RBAC in an
  upgrade of their own.
- **Kubernetes without the hook, Container Apps**: the jobs run with the deployed configuration. Checking a new
  one before it is deployed is not supported: deploy, run `<fullname>-refs` or `<prefix>-refs`
  ([Running a command](commands.md)), and go back on a finding. References fail meanwhile.
- **Docker, a VM**: as the service, with the new file:

  ```sh
  tresor-server refs -resolve -config server.new.yaml
  ```

Fix every finding first: rewrite the references (an administrator), or keep the source or the allowlist entry.

### 2. Deploy

- **Kubernetes**: `helm upgrade` with the new values. The pods carry the configuration's checksum: a change rolls
  them; a change of `env` is in the pod template and rolls them too. A change of a Secret's content the pods read
  is in neither: `kubectl -n tresor rollout restart deploy/<fullname>`.
- **Container Apps**: the recipe's parameters (`issuers`, `admins`, `actors`, `materialAllow`), or - for a
  setting it has no parameter for - the `serviceEnv` variable in your copy of `main.bicep`;
  `az deployment group create` again. The app and the jobs get
  the same settings.
- **Docker, a VM**: restart the service with the new file or environment.

Settings belong in `config` on the chart, not in `env`: the chart derives its RBAC, volumes and admission policy
from `config`.

## Check

- **Readiness**: every replica's `/readyz` is 200 (`kubectl -n tresor rollout status deploy/<fullname>`). Each
  check's status is named - [Incidents](incidents.md#the-service-unready) says what each means.
- **The console's Service screen**: the version, the store, the KEK and any previous one, the issuers, the
  sources and their allowlists, the policy, readiness - as the new configuration has them.
- **`refs`** after the deploy (`<fullname>-refs`, `<prefix>-refs`): exit `0`.
- **The log**: a configuration error stops the start, names the setting, never a value.

## Back

- **Kubernetes**: `helm rollback <release>`. The pods roll back to the old configuration.
- **Container Apps**: deploy the recipe again with the old parameters.
- **Docker, a VM**: restart with the old file.

Nothing in the store depends on the configuration but references (they resolve again with the old sources) and
the KEK: a data key made under a new KEK does not open with the old one alone. A KEK change goes back with the
new one kept in `keys.previous` - see [The KEK](kek.md).
