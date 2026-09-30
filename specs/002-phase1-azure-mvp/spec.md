# Spec 002: phase 1 - the Azure MVP

- **Status**: draft
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

- From tresor at **6133d0d** (main after PR #21): `server/internal/{api,auth,config,mint,testidp}`
  and `cmd/ref-server`, with their tests.
- The commit says so: MIT, from `hugr-lab/tresor`, the same owner; the files keep a note of their
  origin.
- Taken over as they are, then changed in later commits. The first diff against tresor stays small
  and readable.
- The policy code stays inside `internal/api` for now. Moving it to `internal/policy` (spec 001) is a
  refactor for later, not part of the port.

### The module and the layout

- Module `github.com/hugr-lab/tresor-server`, Go 1.26, no cgo.
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
	// one (nil: delete) or an error that aborts. The write is compare-and-set on the row's revision;
	// on a conflict fn runs again on the fresh row, a bounded number of times, then ErrConflict.
	Update(ctx context.Context, name string, fn func(current *Secret) (*Secret, error)) (*Secret, error)
	Delegations() DelegationStore
	DataKeys() DataKeyStore
	Ping(ctx context.Context) error
	Close() error
}
```

- **Why `Update(fn)`**: it is the reference server's own write path. The API's checks (permissions,
  `If-Match`) stay atomic with the write, with no change to the ported handlers.
- **Revision and version are two numbers.**
  - `version` is the protocol's (the ETag). A grant change does not move it.
  - `revision` is the store's: every write moves it, and the compare-and-set is on it.
  - `UPDATE … WHERE name = ? AND revision = ?`, then the rows affected. The same in all three
    dialects; it is what makes several replicas safe.
- **`Secret`** holds what the API needs: the descriptor fields, the grants, and the material.
  In the store, the material is sealed (see *Envelope*); the API sees it open.
- Every replica reads the store on each request. There is no cache of secrets, so a write on one
  replica is seen by the next request on any other.

### Delegation grants in the store

With several replicas, a grant made on one replica must be honoured by the others. So delegation
grants move from the reference server's memory into the store.

```go
type DelegationStore interface {
	Put(ctx context.Context, d Delegation, max int) error    // ErrTooMany at max live grants
	Get(ctx context.Context, idHash []byte) (Delegation, error) // ErrNotFound; an expired one too
	Delete(ctx context.Context, idHash []byte) error
	DeleteWhere(ctx context.Context, actor, subject string) (int, error) // DELETE /v1/delegations
	Purge(ctx context.Context, now time.Time) (int, error)
}
```

- **The id is never stored.** A row is keyed by SHA-256 of the grant id. A leaked table does not
  give usable grants.
- **A row holds**: the actor (owner, client, issuer), the user (the verified caller, as JSON), the
  expiry, and the user's **subject token, sealed** (see *Envelope*; the AAD is the id hash).
- **Minted tokens** (tresor specs/010) stay a per-replica cache, as today. A replica that has none
  mints them lazily from the sealed subject token, while it lives.
- Rows are written once and deleted: no update, so no compare-and-set is needed.
- Expired rows are purged in the background; a read never returns one.

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
| `secrets` | name (PK), type, provider, scope (JSON text), redact_keys (JSON text), comment, owner, version, revision, created_at, updated_at, data_key_id, sealed |
| `grants` | secret (FK, cascade), id, principal, verbs (JSON text); PK (secret, id) |
| `delegations` | id_hash (PK), actor_owner, actor_client, actor_issuer, user_json, expires_at, data_key_id, sealed_subject |
| `data_keys` | id (PK), kek_id, wrapped, created_at, retired_at |
| `lease` | SQLite only: one row, holder, expires_at |

- **Migrations**: at start, under a lock (SQLite: the transaction; PostgreSQL: an advisory lock;
  SQL Server: `sp_getapplock`), so several replicas starting at once apply them once. A binary
  refuses a database whose migration is newer than it knows.
- No upsert, no JSON functions: portable SQL only.

**SQLite** (`modernc.org/sqlite`: pure Go, a distroless image, every platform):
- one replica: development, a laptop, a VM or docker compose;
- WAL, `foreign_keys=ON`, `busy_timeout`;
- **one writer**: at start the service takes the `lease` row (holder, expiry) and renews it. While
  another holder's lease is fresh, it waits, and `/readyz` says not ready.

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
  the limit, delete by actor and subject), data keys, reopening a store, and the revision
  compare-and-set under concurrent writers - two store handles on one database, as two replicas are.
- Run on `memory` and SQLite in process; on PostgreSQL and SQL Server in containers in CI
  (`postgres:17`, `mcr.microsoft.com/mssql/server:2022-latest`; `azure-sql-edge` for arm64
  developers). Locally, the database tests skip when no DSN is given.

### Envelope encryption

- **What is sealed**:
  - a secret's `params` (literals and references alike), as one JSON document. AAD =
    `tresor-server/params/1`, the secret's name and its version. A sealed row copied to another
    name, or to another version, does not open. (Params change only with the version: a grant
    change does not reseal them.)
  - a delegation's subject token. AAD = `tresor-server/delegation/1` and the id hash.
  - AES-256-GCM, a random 96-bit nonce.
- **Data keys**:
  - one active data key; new writes use it;
  - it is wrapped by the KeyWrapper and kept in `data_keys` with the KEK's id (for Key Vault, the key's
    version);
  - a new data key is made when the KEK's version changes, or when the active one is older than
    `keys.data_key_max_age` (default 30 days). Replicas that race to make one: the loser takes the
    winner's (the insert is compare-and-set too);
  - unwrapped data keys are cached in memory for `keys.cache_ttl` (default 5 minutes), never written
    or logged.
- **KeyWrapper**:
  - `local`: a 32-byte key, base64, from a file or an environment variable. AES key wrap (RFC 3394).
    For development, tests and small installs.
  - `azurekeyvault`: a key URL (with no version: wrap with the current one; unwrap with the version
    recorded). `RSA-OAEP-256` for a Key Vault RSA key, `A256KW` on Managed HSM. The service's
    identity needs `Key Vault Crypto User` on the key.
- **Rotation**: a new KEK version gives a new data key for new writes. Old data keys are rewrapped
  under the new version by `tresor-server rewrap` (a command of the binary). Material is never
  re-encrypted for it.
- The `memory` store seals too, with a local KEK made at start: one code path.

### Material by reference: `ref+azkv://`

- **Syntax**: a VARCHAR parameter whose whole value is `ref+azkv://<vault>/<secret>[/<version>]`.
  - `<vault>` is the vault's name: `https://<vault>.vault.azure.net` (another cloud's suffix from
    the config).
  - No version: the current one, read at each fetch. A rotation in the vault reaches DuckDB at its
    next fetch.
- **Allowlist** (`material.azkv.allow`): vaults, each with secret-name prefixes. Nothing else is
  resolved.
- **At write** (`PUT`), for every parameter that starts with `ref+`:
  - an unknown scheme, a malformed reference, or one outside the allowlist: `422 invalid_secret`.
    Never stored as a literal.
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
azure:
  identity: managed              # managed | default (DefaultAzureCredential: az CLI for development)
  client_id: ""                  # a user-assigned managed identity
```

- `state.kind: memory` needs no `keys:`; every other kind refuses to start without it.
- A DSN never carries a password: one there is refused. The password comes from `auth`.
- A `store:` section (the reference server's) is refused with a word on `state:`.

### Health

- `GET /healthz`: the process is up. Nothing else.
- `GET /readyz`: 200 only when all of these answer:
  - the state store (`Ping`); on SQLite, this replica holds the lease;
  - the KEK: a wrap and an unwrap of a test key;
  - every issuer's JWKS.
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
  - `Key Vault Crypto User` on the KEK;
  - `Key Vault Secrets User` on each vault in the allowlist;
  - the database's Entra administrator makes it a database user (a one-time step, in the README and
    a script: Bicep cannot create database users).
- A Container Apps environment, the app with built-in ingress (TLS), two replicas or more.
- The config as a Container Apps secret mounted as a file. It holds no secret itself.
- Optional: a VNet, with private endpoints to Key Vault and the database.
- The cheapest tiers for the live run: PostgreSQL Burstable B1ms; Azure SQL serverless with
  auto-pause.

### CI

- **`go`**: `go vet`, `go test ./...`, `govulncheck`. PostgreSQL and SQL Server as service
  containers, so the StateStore suite runs on all four stores.
- **`conformance`**: tresor's suite against this service.
  - **In tresor, first** (a small tresor PR, not a protocol change): `scripts/ci/test_keycloak.sh`
    takes `TRESOR_SERVER_CMD` (a built server and its config) instead of building `ref-server`.
    One script for both servers.
  - `scripts/ci/tresor_checkout.sh` here checks out tresor at a pinned commit (`TRESOR_COMMIT`),
    with its submodules, as tresor's `acl_checkout.sh` does for duckdb-acl.
  - It builds tresor's `build/release` (the `unittest` runner and the extension). The build directory
    is cached by the pinned commit, so it is built once per pin. ccache helps when the pin moves.
  - A matrix over the state store: `memory`, `sqlite`, `postgres`, `sqlserver`; a local KEK.
  - It runs `test/sql/conformance/*` and tresor's `test/sql/reference_server/*`: the ported API must
    pass the reference server's own tests too.
  - On `postgres`, two replicas of the service behind a round-robin proxy: a grant made on one is
    honoured by the other.
  - The duckdb-acl part (`TRESOR_ACL_EXTENSION`) is not run here: it needs acl built too.
- **`image`**: the Docker build on every PR; the push only from main and tags.

### The PRs

1. **(a) skeleton**: the module, the port from tresor, `state/memory`, `/healthz` `/readyz`, CI with
   conformance on memory (with the tresor hook).
2. **(b) SQL and SQLite**: `sqlstore`, the dialect type, the migrations, the lease, delegations in
   the store, the StateStore suite; conformance on SQLite.
3. **(c) the KEK and the envelope**: `keys`, `local`, `azurekeyvault`, data keys, `rewrap`.
4. **(d) PostgreSQL and SQL Server**: the two dialects, Entra logins, the suite and conformance on
   both, two replicas in CI.
5. **(e) references**: `material`, `azkv`, the allowlist.
6. **(f) the container and Container Apps**: Dockerfile, image CI, the Bicep recipe; the live run.

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
- **Delegation grants at rest**: keyed by a hash, the subject token sealed. The store alone does not
  give a usable grant or token.
- **References**: written only in a `PUT`, which only an administrator makes; checked against the
  allowlist at write and again at each resolution.
- **Identity**: Key Vault and the database through a managed identity. The only static secrets are a
  local KEK and a database password, for development and small installs.
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
- **Minted tokens in the store.** Not needed: the sealed subject token lets any replica mint them.
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

## Open questions

- The region for the live runs: `westeurope`, unless said otherwise.

## Follow-ups

- `internal/policy` out of `internal/api`.
- OpenTelemetry traces and the audit (spec 001).
- A database password as a `ref+azkv://` reference.
- The Kubernetes phase (spec 001's phase 3), then AWS and GCP.
