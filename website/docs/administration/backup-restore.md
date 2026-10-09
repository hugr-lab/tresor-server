---
title: Backup and restore
---

# Backup and restore

**When**: on the database's schedule; before an upgrade; a restore after a loss, a corruption or a failed
upgrade.

**Who**: the platform operator, with the database's and the KEK's administrators.

## What to back up

The store holds everything but the KEK. Material in it is sealed: without the KEK it does not open.

- **The database** (SQLite, PostgreSQL, SQL Server): as any database. It holds the secrets, variables, grants,
  delegation grants and the wrapped data keys.
  - **The installation id** (the `installation` table, made by the migration) is in every MAC of a SQL store. Keep
    it with the backups: lost, every row is refused, and the service never makes a new one.
- **The Kubernetes store**: the namespace's `tresor` resources (`kubectl get tresor`), with Velero or the
  cluster's backup. `state.instance` (the namespace by default) is in every MAC: keep it stable, and restore into
  the same namespace, or set `state.instance` to the old one.
- **The KEK**, as carefully as the backups:
  - **Key Vault**: purge protection on, and every version a backup's data keys name;
  - **Vault Transit**: Vault's own backup. The key is never `exportable` (the service refuses such a key);
  - **AWS KMS, GCP Cloud KMS**: both keys, and every version a backup's data keys name;
  - **a local key**: its value, apart from the database's backups.
- **The configuration**: the chart's values, the recipe's parameters, the file. The KEK's settings name the key.

A backup holds its own data keys. A data key retired since, or a leaked one, still opens it.

## Restore

1. **Stop the service** (Kubernetes: `kubectl -n tresor scale deploy/<fullname> --replicas=0`).
2. **Restore the store**:
   - **a database**: as any database, with its `installation` table;
   - **the Kubernetes store**: the CRDs first. A restore (Velero) writes as another account than the service's:
     remove the admission policy's binding for its duration (step 4 puts it back).

     ```sh
     kubectl delete validatingadmissionpolicybinding <fullname>-<namespace>
     # the restore
     ```

3. **The same KEK and configuration** as when the backup was taken - any previous KEK its data keys are under in
   `keys.previous`. The same version of the service, or a newer one: an older one refuses a database a newer one
   migrated.
4. **Start the service**: on Kubernetes, `helm upgrade` with the release's values - it puts the admission
   policy's binding back and scales the Deployment to its replicas (not before step 3: Helm restores the
   replicas a manual scale set to 0).

   ```sh
   helm upgrade <release> oci://ghcr.io/hugr-lab/charts/tresor-server -n tresor -f values.yaml
   ```

## Check

- **Readiness**: `state` and `keys` are `ok`. On the Kubernetes store, a wrong KEK or instance is not ready (the
  installation's mark does not verify).
- **A read**: a secret reads through the protocol, or the console.
- **`refs`** exits `0`: the references resolve with the configuration.
- **The console's Service screen**: the store, the KEK, the data keys.
- **The log**: no row refused (`tresor.state.left_out` at 0, [Observability](../observability.md#metrics)).
  Minted tokens are minted again.

## Back

Restore again from another backup; the restore replaced the store. What was written after the backup is lost:
grants revoked since are back, secrets deleted since are back. Check them with the secrets administrators.
