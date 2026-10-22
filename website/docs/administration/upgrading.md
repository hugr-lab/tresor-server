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
- **A row whose MAC does not verify is refused** (a read fails, a list leaves it out), where before, with the
  setting unset, it was served and logged: before the upgrade, 0.3's log warns `a row's MAC does not verify`
  for each; after, `tresor.state.left_out` counts them. `mac` gives them a MAC again, if you vouch for them.
- **`cors.allowed_origins`, new**: web pages running tresor in DuckDB-wasm, apart from the console's
  `ui.allowed_origins` ([Configuration](../configuration.md#cors)). Nothing changes until it is set.
- **Signed artifacts**: the image and the chart can be verified before an upgrade
  ([Security](../security.md#verifying-the-artifacts)).

Nothing else: no migration of the Kubernetes store, no CRD changed, no setting renamed.

### Upgrading to 0.5 (spec 023)

- **Kubernetes store: apply the CRDs first** (`kubectl apply --server-side -f crds/`): `TresorSecret` and
  `TresorVariable` have a new field, `dynamic`. With the old CRDs the API server drops it, and a secret with
  generated parameters is refused (its MAC no longer verifies).
- **The SQL stores** migrate at start (a column, `dynamic`): nothing to do.
- **Roll out every replica before writing a generated parameter**: a replica still on 0.4 serves `mint+…` as the
  text it is.
- **`provider: token_exchange` is served as `config`**, the consumer's provider: nothing reads the old name. Its
  `expires_at` is now the token's expiry less `dynamic.margin` (at most half of what is left), not the expiry
  itself: a client fetches a new token sooner.
- **Secrets written before**: not dynamic, so a `mint+…` or `${…}` stored in one is served as it is, until the
  secret is written again. Only an escape changes: `$${` is served as `${`, `mint++` as `mint+`.
- **New, off until set**: service logins call nothing until `dynamic.login_hosts` lists a host; rules and
  `jwt_assertion` use nothing until `dynamic.identities` lists an identity
  ([Generated parameters](../generated.md#service-logins)). A secret of type `tresor_service_login` is never served.
- **ZITADEL key files**: a machine user's key (`userId`, no `clientId`) is now read as that user's client - an
  `exchange.key_file` of such a key names its client by it.

### Upgrading to 0.6 (spec 024)

- **Nothing to migrate**: no column, no CRD change (variables' `dynamic` came with 0.5).
- **Variables take generated values** (`mint+exchange://`, `mint+claim://`, `mint+login://`, `${…}`), served
  `sensitive` with an `expires_at` (tresor spec 037). Roll out every replica before writing one: a replica on 0.5
  serves it as the text it is.
- **A variable written before** is served as written, but for its escapes (`mint++`, `$${`); written again, a text
  that is not a valid generator is refused - write it escaped.
- **A login's scope** begins with the base URL it calls, then base URLs or `variable://<name>` only (a rule's: any
  scheme, within its identity's destinations).
- **A sandboxed DuckDB** (tresor spec 036) stops tresor's own requests: name the service's and the issuers' URLs in
  `allowed_directories` ([Security](../security.md#a-sandboxed-duckdb)).

### Upgrading to 0.7 (spec 026)

- **Nothing to migrate**: no column, no CRD change.
- **New, off until set**: `namespaceOverride` and `clusterIssuer` in the chart; an issuer's `ca_file` and
  `discovery_token_file` ([Kubernetes](../kubernetes.md#the-clusters-own-accounts)). `discovery_token_file` needs
  `ca_file`.
- **The chart's objects now name their namespace** (`metadata.namespace`): the same one as before unless
  `namespaceOverride` is set.

### Upgrading to 0.7.2 (specs 027, 028)

- **Nothing to migrate**: no column, no CRD change; nothing changes until set.
- **`state.auth: vault`** (spec 027): the state's database credentials from a Vault/OpenBao database secrets
  engine, a user per lease; on PostgreSQL `state.vault.set_role` names the group role that owns the tables
  ([OpenBao and Vault](../vault.md#the-databases-credentials)). A database already in use moves to it once its
  tables belong to that group role (`ALTER TABLE … OWNER TO tresor_owner`, or `REASSIGN OWNED BY`).
- **`configTemplate`** (spec 028, the chart): `config` rendered through `tpl` - off by default, the render
  unchanged.

### Upgrading to 0.7.3 (spec 029)

- **Nothing to migrate**; the chart and the configuration are unchanged.
- **The TLS certificate is read again when it changes** (every 30 s): a renewal in place needs no restart. A bad
  new pair leaves the old one serving, and readiness's `tls` check says so (degraded).

### Upgrading to 0.7.4 (spec 030)

- **Nothing to migrate**; nothing changes until set.
- **`whoami` names the person** (`name`), for people to read; a delegation grant made before 0.7.4 has none (a
  new session carries it).
- **An issuer's `ignore_roles`**: roles never taken as principals - before adding one, check no grant or
  `policy.admins` names those roles.

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
