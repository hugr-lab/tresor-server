# Spec 002: phase 1 - the Azure MVP

- **Status**: accepted
- **Date**: 2026-09-30
- **Author**: hugr lab

## Summary

Phase 1 of [spec 001](../001-architecture/spec.md): the first tresor-server that can run in production
on Azure.
- The API layer is taken over from tresor's reference server.
- State is kept in SQLite, PostgreSQL or SQL Server. The two servers allow several replicas.
- Inline material is encrypted under a KEK: a local key, or a key in Azure Key Vault.
- Material can stay in Azure Key Vault Secrets, referenced as `ref+azkv://…`.
- It ships as a distroless image, with an Azure Container Apps recipe on a database.
- tresor's conformance suite runs against it in CI, on every state store.

No protocol change: `protocol.md` in tresor stays as it is.

**A change to spec 001's phases.** PostgreSQL and SQL Server (spec 001's phase 2) move into phase 1:
the Container Apps recipe runs on a database from the start, not on SQLite over Azure Files. Spec
001's later phases (Kubernetes; AWS and GCP) stay as they are.

## Problem

The repository has a spec and a license, no code. Spec 001 splits the work into phases. This spec
fixes the scope and the concrete choices of phase 1, so it can be built in small PRs.

## Design

### The code taken over

- From tresor at **6133d0d** (main after PR #21): `server/internal/{api,auth,config,mint,store,testidp}`
  and `cmd/ref-server`, with their tests. The first commit builds and passes as it is; later commits
  in the same PR replace `internal/store` by `internal/state`.
- The commit says so: MIT, from `hugr-lab/tresor`, the same owner; the files keep a note of their
  origin.
- Taken over as they are, then changed in later commits. The first diff against tresor stays small
  and readable.
- The policy code stays inside `internal/api` for now. Moving it to `internal/policy` (spec 001) is a
  refactor for later, not part of the port.

### The module and the layout

- Module `github.com/hugr-lab/tresor-server`, Go 1.27, no cgo.
- One binary, `cmd/tresor-server`.

```text
cmd/tresor-server                config, wiring, /healthz, /readyz, the listener, `rewrap`
internal/api                     duckdb-secrets/1 routes (ported)
internal/auth                    token verification, principals, the service rule (ported)
internal/config                  the YAML (ported) + state:, keys:, material:, azure:
internal/mint                    token exchange for token_exchange secrets (ported)
internal/testidp                 an OIDC issuer for tests (ported)
internal/azure                   the service's Azure credential (managed identity, or az CLI)
internal/state                   StateStore, Secret, Grant, Delegation, the errors
internal/state/memory            in memory: tests, and a store with no state:
internal/state/sqlstore          one SQL layer; dialects sqlite | postgres | sqlserver
internal/state/sqlstore/migrations/{sqlite,postgres,sqlserver}   embedded SQL
internal/state/statetest         the shared StateStore suite
internal/keys                    KeyWrapper, the envelope (data keys, AES-256-GCM)
internal/keys/local              a 32-byte KEK from a file or the environment
internal/keys/azurekeyvault      wrapKey / unwrapKey in Key Vault or Managed HSM
internal/material                MaterialSource, Ref, the ref+ parser, the allowlist
internal/material/azurekeyvault  Key Vault Secrets
```

### StateStore

Spec 001 sketches the interface. Phase 1 makes it concrete:

```go
type StateStore interface {
	List(ctx context.Context) ([]*Secret, error)
	Get(ctx context.Context, name string) (*Secret, error) // ErrNotFound
	// Update is the one write path: fn gets the current secret (nil when absent) and returns the next
	// one (nil: delete) or an error that aborts. The write is compare-and-set on the version; on a
	// conflict fn runs again on the fresh row, a bounded number of times, then ErrConflict.
	Update(ctx context.Context, name string, fn func(current *Secret) (*Secret, error)) (*Secret, error)
	Delegations() DelegationStore
	DataKeys() DataKeyStore
	Ping(ctx context.Context) error
	Close() error
}
```

- **Why `Update(fn)`**: it is the reference server's own write path. The API's checks (permissions,
  `If-Match`) stay atomic with the write.
- **Compare-and-set on `version`**, the protocol's ETag, and the row's random id. Every write moves
  the version: the ported handlers bump it on a put, a patch and a grant change alike.
  - An update or a delete: `… WHERE name = ? AND version = ? AND row_id = ?`, then the rows
    affected. The row id is there because a secret dropped and created again starts at version 1
    again: without it, a write read before the drop would land on the new secret.
  - A create: `INSERT`; a unique violation is a conflict too (another replica created it first).
  - The secret's row and its `grants` rows change in one transaction.
  - The same in all three dialects; it is what makes several replicas safe.
- **fn may run more than once.** The ported handlers capture state in their closures (`created`,
  `refused`, `missing`). The port resets it at the top of each run, so a retry never answers from a
  former one (a create that lost the race gives 412, not 201).
- **`ErrConflict`** (still conflicting after the retries): `503 service_unavailable`.
- **`Secret`** holds the descriptor fields, the grants, and the params **still sealed**. The API
  opens the params only where it needs them: a fetch with `use`, and the minted secrets a grant's
  exchange looks at. A list opens nothing, so one bad row never fails a whole list.
- Every replica reads the store on each request. There is no cache of secrets, so a write on one
  replica is seen by the next request on any other.

### Delegation grants in the store

With several replicas, a grant made on one replica must be honoured by the others. So delegation
grants move from the reference server's memory into the store.

```go
type DelegationStore interface {
	Put(ctx context.Context, d Delegation, maxPerActor int) error        // ErrTooMany; count and insert in one step
	Count(ctx context.Context, actorOwner string, now time.Time) (int, error) // the check before minting
	Get(ctx context.Context, idHash []byte, now time.Time) (*Delegation, error) // ErrNotFound; an expired one too
	SubjectToken(ctx context.Context, idHash []byte, now time.Time) ([]byte, error) // while it lives
	Delete(ctx context.Context, idHash []byte) (bool, error)
	DeleteWhere(ctx context.Context, actorClient, userOwner string) (int, error) // DELETE /v1/delegations
	// the grant's minted tokens (tresor specs/010), one row per audience and scope
	Token(ctx context.Context, idHash []byte, key string) (*MintedToken, error)
	PutToken(ctx context.Context, idHash []byte, t MintedToken) error // compare-and-set on its version
	Purge(ctx context.Context, now time.Time) (int, error)
}
```

- **The id is never stored.** A row is keyed by SHA-256 of the grant id. A leaked table does not
  give usable grants.
- **A grant row holds**: the actor (owner, client, issuer), the user's owner (for revocation by
  subject), the user (the verified caller, as JSON), the expiry, and the user's subject token.
- **The subject token** is a bearer token for this service. So:
  - it is stored only when the actor may `use` minted secrets (otherwise it is not needed);
  - sealed (see *Envelope*), with its own expiry; never unsealed after it.
- **Minted tokens move into the store too.** A grant lives up to 8 hours; its subject token lives
  minutes to an hour. After that, only the refresh tokens minted at the exchange can renew. With
  several replicas, every replica must see them.
  - One row per grant, audience and scope: the access token and the refresh token, sealed, their
    expiries, a version.
  - A renewal is compare-and-set on that version: refresh tokens rotate, and a replica that loses
    the race takes the winner's tokens instead of spending a refresh token twice.
  - No replica caches them: each request reads the grant and its token from the store. A grant
    revoked on one replica is gone on the next request on any other.
- **The limit** is per actor (`maxPerActor`, default 10000), not global: one actor cannot use up
  every other's. `Put` counts and inserts under a lock: the transaction on SQLite, an advisory lock
  on PostgreSQL, `sp_getapplock` on SQL Server.
- Grant rows are written once and deleted. Expired rows and their tokens are purged every minute
  (and before each new grant); a read never returns one.
- A renewal that loses the race to a replica that wrote a failure (it tried the refresh token this
  one had just spent) writes its good token over the failure, compare-and-set. A renewed token the
  store cannot keep is tried again, then answered as an outage (503): its refresh token is lost.
- One replica's renewals of one token are serialised by a lock per grant and audience; a fresh
  token is served with no lock.
- **Trust**: whoever can write the database is trusted, as with the secrets' grants. The sealed
  values are bound to their grant, but its plain columns (the user's principals, the expiries) are
  not sealed.

### SQL: three dialects

One package, `sqlstore`, with one set of queries in the portable subset. A small dialect type holds
what differs:
- placeholders (`?`, `$1`, `@p1`);
- column types in the DDL (`TEXT` / `NVARCHAR(MAX)`, `BLOB` / `BYTEA` / `VARBINARY(MAX)`,
  timestamps);
- telling a unique violation (→ `ErrExists`) and a transient error (→ retry) apart;
- the connection: the driver, and how it logs in.

The schema (migration `0001`, one SQL file per dialect, applied in `schema_migrations`):

| Table | Columns |
| --- | --- |
| `secrets` | name (PK), row_id (random, per create), type, provider, scope (JSON text), redact_keys (JSON text), comment, owner, version, created_at, updated_at, data_key_id, sealed |
| `grants` | secret (FK, cascade), id, principal, verbs (JSON text); PK (secret, id) |
| `delegations` | id_hash (PK), actor_owner, actor_client, actor_issuer, user_owner, user_json, expires_at, subject_expires_at, data_key_id, sealed_subject; indexes on (actor_owner, expires_at), (user_owner) |
| `delegation_tokens` | id_hash (FK, cascade), mint_key (audience and scope), version, expires_at, data_key_id, sealed; PK (id_hash, mint_key) |
| `data_keys` | id (PK), kek_id, wrapped, created_at, retired_at |
| `active_data_key` | one row: data_key_id, version (compare-and-set) |
| `lease` | SQLite only: one row, holder, expires_at |

- **Migrations**: at start, under a lock (SQLite: the transaction; PostgreSQL: an advisory lock;
  SQL Server: `sp_getapplock`), so several replicas starting at once apply them once. A binary
  refuses a database whose migration is newer than it knows.
- No upsert, no JSON functions: portable SQL only.

**SQLite** (`modernc.org/sqlite`: pure Go, a distroless image, every platform):
- one replica: development, a laptop, a VM or docker compose;
- WAL, `foreign_keys=ON`, `busy_timeout`;
- **one writer**: at start the service takes the `lease` row (holder, expiry) and renews it. While
  another holder's lease is fresh, it waits: it serves no request, and `/readyz` says not ready.
  - The migrations run once the lease is held: a waiting replica never changes the schema under the
    one that serves.
  - Fencing: the holder serves only until its own monotonic deadline, 5 s before the expiry it wrote
    (15 s, renewed every 5 s). A paused process stops serving before another may take over; the
    replicas' clocks may differ by up to 5 s.
  - This changes spec 001 ("refuses to start"): waiting lets a new revision start next to the old one
    and take over when it stops, with no restart loop.

**PostgreSQL** (`pgx`, through `database/sql`):
- several replicas;
- `auth: entra`: the password is an Entra token for `https://ossrdbms-aad.database.windows.net`,
  fetched with the service's identity in `BeforeConnect`, for each new connection. The database
  role is the managed identity's (Azure Database for PostgreSQL Flexible Server).
- `auth: password`: from `password_env` or `password_file`, read again for each new connection: a
  rotation needs no restart.

**SQL Server / Azure SQL** (`go-mssqldb`):
- several replicas;
- `auth: entra`: an access-token connector (`mssql.NewConnectorWithAccessTokenProvider`), the token
  for `https://database.windows.net` from the service's identity. No password at all. The database
  user is created `FROM EXTERNAL PROVIDER` for the managed identity.
- `auth: password`: as for PostgreSQL.
- Snapshot isolation is not needed: the compare-and-set is a single `UPDATE`.

A database password as a `ref+azkv://` reference (spec 001) is a follow-up; phase 1 logs in with
Entra on Azure.

### The shared StateStore suite

- `internal/state/statetest.Run(t, func() StateStore)`: one suite, every store.
- It covers: create, get, list order, update, delete, `ErrNotFound`, grants, delegations (expiry,
  the limit, delete by actor and subject), data keys, reopening a store, and the version
  compare-and-set under concurrent writers - two store handles on one database, as two replicas are.
- Run on `memory` and SQLite in process; on PostgreSQL and SQL Server in containers in CI
  (`postgres:17`, `mcr.microsoft.com/mssql/server:2022-latest`). Azure SQL Edge is retired: on an
  arm64 laptop, SQL Server runs under emulation, or its tests run in CI only.
- Locally, the database tests skip when no DSN is given.

### Envelope encryption

- **What is sealed**:
  - a secret's `params` (literals and references alike), as one JSON document. AAD =
    `tresor-server/params/1`, the row's random id, the secret's name and its version. A sealed
    value copied to another row, name or version does not open; nor does one from a dropped and
    recreated secret of the same name. Every write reseals.
  - a delegation's subject token: AAD = `tresor-server/delegation/1` and the id hash.
  - a grant's minted tokens: AAD = `tresor-server/minted/1`, the id hash, the mint key and the version.
  - AES-256-GCM, a random 96-bit nonce.
- **Data keys**:
  - one active data key; new writes use it;
  - it is wrapped by the KeyWrapper and kept in `data_keys` with the KEK's id (for Key Vault, the key's
    version);
  - a new data key is made when the KEK's version changes, or when the active one is older than
    `keys.data_key_max_age` (default 30 days);
  - the active one is named in the `active_data_key` row, changed by compare-and-set on its version.
    Replicas that race to make a new one: the loser drops its own and takes the winner's;
  - unwrapped data keys are cached in memory for `keys.cache_ttl` (default 5 minutes), never written
    or logged.
- **KeyWrapper**:
  - `local`: a 32-byte key, base64, from a file or an environment variable. AES key wrap (RFC 3394).
    For development, tests and small installs.
  - `azurekeyvault`: a key URL, in a Key Vault or a Managed HSM (with no version: wrap with the
    current one; unwrap with the version recorded).
    - The algorithm follows the key's type: `RSA-OAEP-256` for an RSA key (either service);
      `A256KW` for an AES key (Managed HSM only).
    - Key Vault with the RBAC permission model: the service's identity needs
      `Key Vault Crypto Service Encryption User` on the key (get, wrap, unwrap; nothing more).
    - Managed HSM: its local RBAC, `Managed HSM Crypto Service Encryption User` on the key.
- **Rotation**: a new KEK version gives a new data key for new writes. Old data keys are rewrapped
  under the new version by `tresor-server rewrap` (a command of the binary). Material is never
  re-encrypted for it.
  - A data key records the KEK id it was wrapped under: for Key Vault, the key's full id (with its
    version) and the algorithm (`…/keys/<name>/<version>#RSA-OAEP-256`). The current version is read
    from the vault at most once a minute.
  - `rewrap` runs next to the service; it changes each data key compare-and-set.
  - It moves data keys between versions of one KEK. Moving to another KEK (local to Key Vault) is a
    follow-up.
  - A data key of another vault or key is never sent anywhere: it is `ErrSealed`.
- The `memory` store does not seal: it has nothing at rest. It behaves as the others otherwise (a list
  carries no params).
- A secret whose params do not open is not rewritten either: an update of it fails, as a read does.
  An administrator may delete it: nothing that opens is lost.
- Only a read with `use` opens params (`Get`). A descriptor, a permission, a list open nothing
  (`Describe`, `List`): with the KEK down they still answer, and a broken secret does not tell a
  caller with no verb that its name exists.
- A value that does not open is `503 service_unavailable`, as the protocol has no other type for it.
  It is not transient; a type of its own would be a protocol change (a follow-up for tresor).

### Material by reference: `ref+azkv://`

- **Syntax**: a VARCHAR parameter whose whole value is `ref+azkv://<vault>/<secret>[/<version>]`.
  - `<vault>` is the vault's name: `https://<vault>.vault.azure.net` (another cloud's suffix from
    the config).
  - Strict: vault and secret names `[0-9A-Za-z-]`, a version 32 hex digits. No escapes, no `%`, no
    other path segment, no query. The URL to Key Vault is built from the parsed parts, never from
    the text.
  - Key Vault names are case-insensitive: vaults and prefixes are compared without case.
  - No version: the current one, read at each fetch. A rotation in the vault reaches DuckDB at its
    next fetch.
- **Allowlist** (`material.azkv.allow`): vaults, each with secret-name prefixes. Nothing else is
  resolved.
- **At write** (`PUT`), for every parameter that starts with `ref+`:
  - an unknown scheme, a malformed reference, or one outside the allowlist: `422 invalid_secret`.
    Never stored as a literal.
  - a reference in a value that is not VARCHAR, or in a `token_exchange` secret: `422`.
  - a parameter holding a reference is added to `redact_keys`, if the caller left it out: the
    resolved value must never show in `duckdb_secrets()`.
  - the write is an administrator's anyway (tresor specs/009); the check does not depend on it.
  - the reference is not resolved at write: a secret may be written before its vault value exists.
- **At fetch** (`GET /v1/secrets/{name}` with `use`):
  - each reference is resolved with the service's identity (`Key Vault Secrets User`);
  - the allowlist is checked again: the config may have changed;
  - any failure (not found, denied, disabled, outside the allowlist, unreachable) is
    `503 service_unavailable` for this fetch. Never an empty or a stale value.
  - `material.azkv.cache_ttl` (default 0: none) allows a short cache, for vault request limits.
- **The log** records each resolution: the secret's name, the vault, the Key Vault secret's name and
  version. Never the value.
- A reference is never returned as such: callers see the resolved value, and only with `use`.

### Configuration

The reference server's YAML (unknown keys are errors), minus its `store:`, plus:

```yaml
state:
  kind: postgres                 # memory | sqlite | postgres | sqlserver
  # sqlite:    path: /data/tresor.db
  # postgres:  dsn: host=corp-pg.postgres.database.azure.com dbname=tresor user=tresor-id sslmode=require
  # sqlserver: dsn: sqlserver://corp-sql.database.windows.net?database=tresor
  auth: entra                    # entra | password (password_env or password_file)
  max_open_conns: 10
keys:
  kind: azurekeyvault            # local | azurekeyvault
  key: https://corp-kv.vault.azure.net/keys/tresor-kek
  # local: {kind: local, key_env: TRESOR_KEK} or {kind: local, key_file: /run/secrets/kek}
  data_key_max_age: 720h
  cache_ttl: 5m
material:
  azkv:
    allow:
      - vault: corp-vault
        prefixes: [duckdb-, lake-]
    cache_ttl: 0s
tls:
  offload: true                  # TLS ends at the platform's ingress (Container Apps); see below
azure:
  identity: managed              # managed | default (DefaultAzureCredential: az CLI for development)
  client_id: ""                  # a user-assigned managed identity
```

- `state.kind: memory` needs no `keys:`; every other kind refuses to start without it.
- A DSN never carries a password: one there is refused. The password comes from `auth`.
- A `store:` section (the reference server's) is refused with a word on `state:`.
- **`tls.offload`**: the reference server refuses plain http on a non-loopback address. Container
  Apps ends TLS at its ingress and forwards plain http to the container. With `offload: true`:
  - the service listens with plain http on any address;
  - `public_url` must be `https`;
  - the README says the port must be reachable only through the ingress (Container Apps: no
    external port but the ingress's).

### Configuration from the environment

In containers, Kubernetes and Container Apps, the configuration often comes from environment
variables, not a file. Every setting can be given there. The sources, in order, each over the last
(loaded with [viper](https://github.com/spf13/viper): the layering and the merge are its):

1. **the file**, `-config <path>`. Optional now: without it, the configuration starts empty.
2. **`TRESOR_CONFIG`**: the whole YAML document in one variable, in place of a file.
3. **one variable per setting**: `TRESOR_` and the setting's path in capitals, `__` between the
   levels.
   - `TRESOR_LISTEN=0.0.0.0:8080`, `TRESOR_PUBLIC_URL=https://secrets.corp.example`
   - `TRESOR_STATE__KIND=postgres`, `TRESOR_STATE__DSN=host=… dbname=tresor`, `TRESOR_STATE__AUTH=entra`
   - `TRESOR_KEYS__KIND=azurekeyvault`, `TRESOR_KEYS__KEY=https://corp-kv.vault.azure.net/keys/tresor-kek`
   - A text setting takes the value as it is (a URL with `#`, a DSN, `null`: all text).
   - A list, a section or a number is read as YAML, so it fits in one variable:
     `TRESOR_POLICY__ADMINS=[role:secrets_admin]`,
     `TRESOR_ISSUERS=[{issuer: https://login.microsoftonline.com/<tenant>/v2.0, audience: api://tresor}]`.
   - A variable replaces the whole value at its path. A list is given whole: its items cannot be set
     one by one (`TRESOR_ISSUERS__0__…` is an error).
   - A section is set by its keys (`TRESOR_STATE__KIND`), not whole (`TRESOR_STATE` is an error); a
     whole document goes in `TRESOR_CONFIG`.
   - Names are in capitals: `TRESOR_state__kind` is an error.

Rules:
- The result is validated as a file is: unknown keys are errors.
- **No weak typing.** A number or a flag where a text belongs is an error, never converted
  (`audience: 0123` must be quoted, not become `83`). Keys are exact: `Listen:`, a key twice, or a
  dotted key (`policy.admins:`) in a document is an error.
- An empty variable is an empty text: it clears what the file set.
  - Only a variable named after a setting is read as configuration (`TRESOR_LISTEN`,
    `TRESOR_STATE__…`, …; `TRESOR_CONFIG`).
  - A typo is an error, not ignored: a name with `__`, or a top-level setting's name and `_`, that
    names no setting (`TRESOR_STATE__KNID`, `TRESOR_STATE_KIND`, `TRESOR_POLICIES__ADMINS`).
  - Other `TRESOR_` variables are left alone: the ones a `*_env` setting names (whatever their
    shape: `TRESOR_ISSUERS_SECRET` too), and tresor's test variables.
  - A `*_env` setting may not name a variable that is read as configuration: its secret would be
    configuration too.
- **No secret in the configuration**, from a file or from the environment. Secrets stay where
  their settings name them (`client_secret_env`, `password_env`, `key_env`): a Kubernetes Secret or a
  Container Apps secret, as an environment variable of its own.
- At start, the log names the settings that came from the environment, never their values. A
  configuration error quotes no value either: a secret put in the wrong place stays out of the log.
- No `${VAR}` expansion inside the YAML: one way to use the environment, not two.

### Health

- `GET /healthz`: the process is up. Nothing else.
- `GET /readyz`: 200 only when all of these answer:
  - the state store (`Ping`); on SQLite, this replica holds the lease;
  - the KEK: a wrap and an unwrap of a test key;
  - every issuer's JWKS, **once**: at start, until each has been fetched. After that an issuer's
    outage is reported in the answer but does not make the replica unready (keys it has cached keep
    working). Otherwise one IdP's outage would take every replica out. (A change to spec 001.)
- Checks run in the background every 30 s, so a probe never calls Key Vault itself. The answer names
  the failing check, never a value.
- Neither route needs a token. Both are outside the protocol's `/v1`.

### The container

- A multi-stage `Dockerfile`: `golang` to build (`CGO_ENABLED=0`, `-trimpath`), then
  `gcr.io/distroless/static-debian12:nonroot`.
- linux/amd64 and linux/arm64.
- Published to `ghcr.io/hugr-lab/tresor-server`: `:edge` from main, `:vX.Y.Z` from tags.

### The Azure Container Apps recipe

Under `deploy/azure-container-apps/`: a Bicep template and a README. A parameter picks the database:
`postgres` (Azure Database for PostgreSQL Flexible Server) or `sqlserver` (Azure SQL Database).
- A user-assigned managed identity:
  - `Key Vault Crypto Service Encryption User` on the KEK (the vault on the RBAC permission model);
  - `Key Vault Secrets User` on each vault in the allowlist;
  - the database's Entra administrator makes it a database user (a one-time step, in the README and
    a script: Bicep cannot create database users).
- A Container Apps environment, the app with built-in ingress (TLS), two replicas or more.
- The configuration as environment variables of the app (`TRESOR_…`); nothing to mount.
- Optional: a VNet, with private endpoints to Key Vault and the database.
- The cheapest tiers for the live run: PostgreSQL Burstable B1ms; Azure SQL serverless with
  auto-pause.

### CI

- **`go`**: `go vet`, `go test ./...`, `govulncheck`. PostgreSQL and SQL Server as service
  containers, so the StateStore suite runs on all four stores.
- **`conformance`**: tresor's suite against this service.
  - **In tresor** (tresor PR #22, merged as `1a043ad`; not a protocol change):
    `scripts/ci/test_keycloak.sh` takes `TRESOR_SERVER_CMD` instead of building `ref-server`. One
    script for both servers. Its header is the contract; in short:
    - The command is one simple command that is the server (`exec`): a built binary, no `&&`, no
      `VAR=value` prefix (exported before the script), no `go run` or `docker run`.
    - `TRESOR_SERVER_WAIT` (seconds, default 10) is raised for the database stores: migrations and
      the first connection come before the discovery answers.
    - The service matches tresor's test `server.yaml`: plain http on `127.0.0.1`, the issuer, the
      roles claim, the admins, the actor `client:acl-node`, the exchange client. Only the literal
      `127.0.0.1:18480` and `127.0.0.1:18443` are rewritten, never `localhost:`.
    - Its environment: `TRESOR_TEST_SERVER_CONFIG` (the config on this run's ports), `KEYCLOAK_PORT`,
      `TRESOR_SERVER_PORT`, `TRESOR_EXCHANGE_SECRET`.
    - `TRESOR_SERVER_CONFIG` names our config template (`testdata/keycloak/server.yaml`, with a
      `state:` and `keys:` per store).
    - The duckdb-acl part greps the server's log for the request lines (`method=… path=… status=…`,
      slog text). The port keeps that log line as it is.
  - `scripts/ci/tresor_checkout.sh` here checks out tresor at a pinned commit (`TRESOR_COMMIT`),
    with its submodules, as tresor's `acl_checkout.sh` does for duckdb-acl.
  - One job builds tresor's `build/release` (the `unittest` runner and the extension) and passes it
    to the others as an artifact. The build is cached by the pinned commit, so it is built once per
    pin. ccache helps when the pin moves.
  - `TRESOR_COMMIT` = `1a043ad4cb361c3af9709ae847ae8bd696b82f82`.
  - A matrix over the state store: `memory`, `sqlite`, `postgres`, `sqlserver`; a local KEK.
  - It runs `test/sql/conformance/*` and tresor's `test/sql/reference_server/*`: the ported API must
    pass the reference server's own tests too.
  - On `postgres`, two replicas of the service behind a round-robin proxy. The hook takes one
    command that is the server, so a small built Go binary (`internal/ci/replicas`, not shipped) is
    that command: it starts the two replicas, proxies to them, and stops them when it is stopped.
    Their logs are passed through, so the acl part still finds its request lines. a grant made on one is honoured by
    the other. A Go test covers what that run cannot: a grant's minted token renewed on another
    replica after its subject token has expired.
  - The duckdb-acl part (`TRESOR_ACL_EXTENSION`) is not run here: it needs acl built too.
- **`image`**: the Docker build on every PR; the push only from main and tags.

### The PRs

1. **(a) skeleton**: the module, the port from tresor, `state/memory`, `/healthz` `/readyz`, CI with
   conformance on memory (with the tresor hook).
2. **(b) SQL, SQLite and the envelope**: `sqlstore`, the dialect type, the migrations, the lease, the
   StateStore suite; `keys`, the envelope, data keys, the `local` KEK. SQLite never holds material in
   the clear, so the envelope comes with it. Conformance on SQLite.
3. **(c1) delegations**: delegations and their minted tokens in the store, sealed from the start.
4. **(c2) Key Vault**: the `azurekeyvault` KEK, `rewrap`.
5. **(d) PostgreSQL and SQL Server**: the two dialects, Entra logins, the suite and conformance on
   both, two replicas in CI.
6. **(e) references**: `material`, `azkv`, the allowlist.
7. **(f) the container and Container Apps**: `tls.offload`, Dockerfile, image CI, the Bicep recipe; the live run.

The docs site (Docusaurus, as tresor's `website/`) comes with or after (f).

## Enforcement & security

- **Fail closed:**
  - a data key that does not unwrap, or a sealed row that does not open: 503 for that request, and
    the row is never rewritten blind;
  - a reference that does not resolve: 503 for that fetch;
  - an unreachable store: 503;
  - a store kind other than `memory` without a KEK: the service does not start;
  - a KEK or a database that does not answer at start: the service starts, but not ready.
- **Nothing sensitive in a log or an error**: no material, no token, no data key, no delegation id,
  no resolved value. Errors name the secret, the vault or the key, never a value. A driver's error
  is logged only after the DSN is stripped from it.
- **Delegation grants at rest**: keyed by a hash; the subject token and the minted tokens sealed.
  The store alone does not give a usable grant or token.
- **Revocation** reaches every replica at its next request: a grant is read from the store each
  time, and a replica's token cache is dropped with it.
- **References**: written only in a `PUT`, which only an administrator makes; checked against the
  allowlist at write and again at each resolution.
- **Identity**: Key Vault and the database through a managed identity. Static secrets:
  - a local KEK and a database password, for development and small installs;
  - the token-exchange client secret (`issuers[].exchange.client_secret_env`, tresor specs/010),
    when minted secrets are used. Replacing it by a federated credential of the managed identity is
    a follow-up.
- **Replicas**: only on PostgreSQL and SQL Server. SQLite holds one replica by the lease row.
- **Across versions**: the schema carries its migration number; a binary refuses a database newer
  than it knows. The sealed formats carry their version in the AAD.

## Testing

- Go tests: the ported tests, the StateStore suite (memory, SQLite, PostgreSQL, SQL Server), the
  envelope (tampered rows, a wrong name or version in the AAD, rotation), the `ref+` parser and the
  allowlist, `azkv` against a fake Key Vault (`httptest`).
- tresor's conformance suite and the reference server's tests, with Keycloak, on all four stores;
  two replicas on PostgreSQL.
- Live, by hand (like tresor's `scripts/dev/entra_live.sh`), with the Entra tenant and its
  subscription, in one resource group (`tresor-server-live`, `westeurope`) that is deleted after:
  - `scripts/dev/azure_live.sh`: a real Key Vault KEK and a `ref+azkv://` secret, used from DuckDB by
    an Entra person and an Entra node, with the service running locally (az CLI identity);
  - then the same against the Container Apps deployment, once on PostgreSQL and once on Azure SQL.

## Alternatives considered

- **SQLite on Azure Files for Container Apps.** One replica, and WAL does not work on a network
  share. A database from the start gives replicas and no file share.
- **Delegations kept in memory.** Wrong with several replicas: a grant made on one replica would be
  unknown to the others.
- **Minted tokens per replica only** (as the reference server). A grant would stop minting on the
  other replicas once its subject token expired. Session affinity would hide it, not fix it.
- **Sealing each parameter apart** (spec 001's wording). One sealed document per secret is simpler
  and hides which parameters there are. No property is lost.
- **Resolving references at write.** It would copy material, or fail a write before the vault is
  ready. Resolution at fetch is what makes rotation work.
- **A conformance kit from tresor** (the `unittest` runner and tests as a release artifact): no C++
  build here. Better later; it needs a tresor release change first.

## Decisions (2026-09-30)

- **The subscription** for live runs: the one in the Entra tenant ("Azure subscription 1"), in one
  resource group deleted after each run.
- **The conformance runner**: a hook in tresor's `test_keycloak.sh` (the tresor session makes it).
- **Container Apps runs on a database**: PostgreSQL and SQL Server both move into phase 1.
- **The image registry**: `ghcr.io/hugr-lab/tresor-server`.

- **The region** for live runs: `westeurope`.
- **Configuration from the environment** (the owner's addition): every setting, as `TRESOR_CONFIG`
  or one `TRESOR_<PATH>` variable per setting.

## Open questions

- None.

## Follow-ups

- `internal/policy` out of `internal/api`.
- OpenTelemetry traces and the audit (spec 001).
- A database password as a `ref+azkv://` reference.
- The token-exchange client as a federated credential of the managed identity: no client secret.
- The Kubernetes phase (spec 001's phase 3), then AWS and GCP.
