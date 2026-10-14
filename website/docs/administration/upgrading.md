---
title: Upgrading
---

# Upgrading

**When**: a new version of the service, or of the chart.

**Who**: the platform operator.

## What happens at start

- **Migrations run at start**, one replica at a time (a lock in the database). The Kubernetes store has none: its
  CRDs are the chart's.
- **An older binary refuses a database migrated by a newer one**, never writes it. Going back is a restore.
- A command run with a newer image than the service's migrates the database too: run the service's own version
  ([Running a command](commands.md)).

## Steps

1. **Read the release notes** ([GitHub releases](https://github.com/hugr-lab/tresor-server/releases)) of every version between the running one and the new one: a step of its own, a
   CRD changed, a setting renamed.
2. **Back up** the database, or the namespace's `tresor` resources ([Backup and restore](backup-restore.md)).
3. **The CRDs** (Kubernetes store): Helm installs `crds/` on the first install only, and never upgrades them. An
   upgrade that changes them says so: apply them first.

   ```sh
   kubectl apply --server-side -f crds/
   ```

   Variables (spec 004) brought `TresorVariable`: an install from before needs it, or the service does not start.
4. **The image**, in an upgrade of its own - not with a configuration change:
   - **Kubernetes**: `helm upgrade` with the new chart version (its `appVersion`) or `image.tag`. The
     `refsBeforeUpgrade` hook does not run when the image changes.
   - **Container Apps**: the recipe again with `-p image=ghcr.io/hugr-lab/tresor-server:<version>`. A version
     tag, not `edge`.
   - **Docker, a VM**: the new image or binary, one replica at a time.
5. **The version's own steps**, once every replica runs it (below).

## Steps a version asks for

### Authenticated data keys (spec 003)

Data keys made before carry no tag, and every value sealed under them is refused (`500`) until they are tagged.
Once, with the new version:

1. **Key Vault**: give the KEK the `sign` operation (`az keyvault key set-attributes --vault-name <vault> --name
   <key> --ops wrapKey unwrapKey sign`, or rotate it with those operations), and the service's identity the
   custom role (get, wrap, unwrap, sign) on the key ([Encryption](../encryption.md#the-root)).
2. **`rewrap -tag-untagged`**: it tags the data keys that have none - you vouch for the store as it is - and logs
   each one. No job runs it: on Kubernetes, a job rendered from `<fullname>-rewrap` with its arguments changed
   ([Running a command](commands.md#kubernetes-the-chart)); on Container Apps, not supported by the recipe; a VM:

   ```sh
   tresor-server rewrap -tag-untagged -config server.yaml
   ```

### The SQL stores' MAC (spec 014; on by default since 0.4)

From 0.4 the checks are on unless `state.mac: false`. A database whose rows were all written by 0.2 or later
needs nothing. One with rows from before 0.2 (no MAC) makes the start stop, naming how many:

1. `mac` (`<fullname>-mac`, `<prefix>-mac`; on SQLite with the service stopped) with the new version. Rows with no
   MAC, or a stale one, get one: you vouch for the database. A row that cannot be given one (its data key gone) is
   named, and the command exits `1`.
2. Start the service. To start first and fill later: `state.mac: false` for now
   ([Changing the configuration](configuration.md)), then remove it after `mac`.

- The refused start has already migrated the database (the MAC's columns come with it): going back to a version
  before 0.2 means restoring the backup.
- `rewrap` and `reseal` open the store as the service does: on such a database they stop with the same message -
  `mac` first, or `TRESOR_STATE__MAC=false` for that run.

### Upgrading to 0.4 (spec 022)

- **`state.mac` on by default** on the SQL stores (above): a database with rows from before 0.2 needs `mac` once,
  or the start stops and says so. See [State](../state.md#the-sql-stores-mac-statemac).
- **`cors.allowed_origins`, new**: web pages running tresor in DuckDB-wasm, apart from the console's
  `ui.allowed_origins` ([Configuration](../configuration.md#cors)). Nothing changes until it is set.
- **Signed artifacts**: the image and the chart can be verified before an upgrade
  ([Security](../security.md#verifying-the-artifacts)).

Nothing else: no migration of the Kubernetes store, no CRD changed, no setting renamed.

## Check

- Every replica ready, on the new version: the console's Service screen names it.
- A secret written before the upgrade reads.
- `refs` exits `0` (`<fullname>-refs`, `<prefix>-refs`).
- No `500` in the log for a data key or a row.

## Back

- **Before a migration**: the old image.
- **After one**: the old binary refuses the database. Roll forward, or restore the backup from step 2 with the
  old image - writes made since are lost.
- **The MAC checks**: `state.mac: false` and deploy; the MACs stay written.
