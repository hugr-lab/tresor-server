# Spec 002: phase 1 - the Azure MVP

- **Status**: draft
- **Date**: 2026-09-30
- **Author**: hugr lab

## Summary

Phase 1 of [spec 001](../001-architecture/spec.md): the first tresor-server that can run in production
on Azure.
- The API layer is taken over from tresor's reference server.
- State is kept in SQLite.
- Inline material is encrypted under a KEK: a local key, or a key in Azure Key Vault.
- Material can stay in Azure Key Vault Secrets, referenced as `ref+azkv://…`.
- It ships as a distroless image, with an Azure Container Apps recipe.
- tresor's conformance suite runs against it in CI.

No protocol change: `protocol.md` in tresor stays as it is.

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
cmd/tresor-server              config, wiring, /healthz, /readyz, the listener
internal/api                   duckdb-secrets/1 routes (ported)
internal/auth                  token verification, principals, the service rule (ported)
internal/config                the YAML (ported) + state:, keys:, material:
internal/mint                  token exchange for token_exchange secrets (ported)
internal/testidp               an OIDC issuer for tests (ported)
internal/state                 StateStore, Secret, Grant, the errors
internal/state/memory          in memory: tests, and a store with no state:
internal/state/sqlite          modernc.org/sqlite, embedded migrations
internal/state/statetest       the shared StateStore suite
internal/keys                  KeyWrapper, the envelope (data keys, AES-256-GCM)
internal/keys/local            a 32-byte KEK from a file or the environment
internal/keys/azurekeyvault    wrapKey / unwrapKey in Key Vault or Managed HSM
internal/material              MaterialSource, Ref, the ref+ parser, the allowlist
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
  - `UPDATE … WHERE name = ? AND revision = ?`, then the rows affected.
- **`Secret`** holds what the API needs: the descriptor fields, the grants, and the material.
  In the store, the material is sealed (see *Envelope*); the API sees it open.
- **Delegation grants stay in memory** in phase 1, as in the reference server:
  - a grant carries the user's minted tokens (tresor specs/010);
  - one replica needs nothing more;
  - phase 2 (several replicas) moves them into the store, sealed. `Delegations()` is left out of the
    interface until then.

### SQLite

- `modernc.org/sqlite`: pure Go, so a distroless image and every platform.
- Schema (migration `0001`), embedded SQL files, in `schema_migrations`:

| Table | Columns |
| --- | --- |
| `secrets` | name (PK), type, provider, scope (JSON text), redact_keys (JSON text), comment, owner, version, revision, created_at, updated_at, data_key_id, sealed (BLOB) |
| `grants` | secret (FK, cascade), id, principal, verbs (JSON text); PK (secret, id) |
| `data_keys` | id (PK), kek_id, wrapped (BLOB), created_at, retired_at |
| `lease` | one row: holder, expires_at |

- Pragmas: `foreign_keys=ON`, `busy_timeout`, and the journal mode from the config:
  - `wal` (default) on a local disk;
  - `delete` on a network share (Azure Files), where WAL's shared memory does not work.
- **One writer.** SQLite never runs with two replicas:
  - at start the service takes the `lease` row (holder, expiry), and renews it;
  - while another holder's lease is fresh, it waits, and `/readyz` says not ready;
  - a lease row, not a file lock: file locks are not reliable on Azure Files.

### The shared StateStore suite

- `internal/state/statetest.Run(t, func() StateStore)`: one suite, every store.
- It covers: create, get, list order, update, delete, `ErrNotFound`, grants, the revision
  compare-and-set under concurrent writers, data keys, and reopening a store.
- Phase 1 runs it on `memory` and `sqlite`. PostgreSQL and SQL Server (phase 2) reuse it as it is.

### Envelope encryption

- **What is sealed**: a secret's `params` (literals and references alike), as one JSON document.
  - AES-256-GCM, a random 96-bit nonce.
  - AAD = `tresor-server/params/1`, the secret's name and its version. A sealed row copied to
    another name, or to another version, does not open. (Params change only with the version: a
    grant change does not reseal them.)
- **Data keys**:
  - one active data key; new writes use it;
  - it is wrapped by the KeyWrapper and kept in `data_keys` with the KEK's id (for Key Vault, the key's
    version);
  - a new data key is made when the KEK's version changes, or when the active one is older than
    `keys.data_key_max_age` (default 30 days);
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
  kind: sqlite                   # memory | sqlite
  path: /data/tresor.db
  journal: wal                   # wal | delete (a network share)
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

- `state.kind: memory` needs no `keys:`. `sqlite` refuses to start without `keys:`.
- A `store:` section (the reference server's) is refused with a word on `state:`.

### Health

- `GET /healthz`: the process is up. Nothing else.
- `GET /readyz`: 200 only when all of these answer:
  - the state store (`Ping`), and this replica holds the SQLite lease;
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

Under `deploy/azure-container-apps/`: a Bicep template and a README.
- A user-assigned managed identity:
  - `Key Vault Crypto User` on the KEK;
  - `Key Vault Secrets User` on each vault in the allowlist.
- A Container Apps environment, the app with built-in ingress (TLS), one replica (min 1, max 1).
- An Azure Files share for SQLite, mounted with `nobrl`, and `state.journal: delete`.
- The config as a Container Apps secret mounted as a file. It holds no secret itself.
- Optional: a VNet, with private endpoints to Key Vault and storage.

### CI

- **`go`**: `go vet`, `go test ./...` (the StateStore suite on memory and SQLite, the envelope, the
  references against a fake Key Vault), `govulncheck`.
- **`conformance`**: tresor's suite against this service.
  - `scripts/ci/tresor_checkout.sh` checks out tresor at a pinned commit (`TRESOR_COMMIT`), with its
    submodules, as tresor's `acl_checkout.sh` does for duckdb-acl.
  - It builds tresor's `build/release` (the `unittest` runner and the extension). The build directory
    is cached by the pinned commit, so it is built once per pin. ccache helps when the pin moves.
  - Keycloak from tresor's `server/docker-compose.yml` and realm.
  - tresor-server started with a config for that Keycloak, once per state store (`memory`,
    `sqlite`), with a local KEK.
  - It runs `test/sql/conformance/*` and tresor's `test/sql/reference_server/*`: the ported API must
    pass the reference server's own tests too.
  - The duckdb-acl part (`TRESOR_ACL_EXTENSION`) is not run here: it needs acl built too.
- **`image`**: the Docker build on every PR; the push only from main and tags.

### The PRs

1. **(a) skeleton**: the module, the port from tresor, `state/memory`, `/healthz` `/readyz`, CI with
   conformance on memory.
2. **(b) SQLite**: `state/sqlite`, the migrations, the lease, the StateStore suite; conformance on
   SQLite.
3. **(c) the KEK and the envelope**: `keys`, `local`, `azurekeyvault`, data keys, `rewrap`.
4. **(d) references**: `material`, `azkv`, the allowlist; a live script.
5. **(e) the container and Container Apps**: Dockerfile, image CI, the Bicep recipe; a live run.

The docs site (Docusaurus, as tresor's `website/`) comes with or after (e).

## Enforcement & security

- **Fail closed:**
  - a data key that does not unwrap, or a sealed row that does not open: 503 for that request, and
    the row is never rewritten blind;
  - a reference that does not resolve: 503 for that fetch;
  - `sqlite` without a KEK: the service does not start;
  - a KEK that does not answer at start: the service starts, but not ready.
- **Nothing sensitive in a log or an error**: no material, no token, no data key, no delegation id,
  no resolved value. Errors name the secret, the vault or the key, never a value.
- **References**: written only in a `PUT`, which only an administrator makes; checked against the
  allowlist at write and again at each resolution.
- **Identity**: Key Vault through a managed identity. The only static secret is a local KEK, for
  development and small installs.
- **One replica on SQLite**, held by the lease row.
- **Across versions**: the schema carries its migration number; a binary refuses a database newer
  than it knows. The sealed format carries its version in the AAD.

## Testing

- Go tests: the ported tests, the StateStore suite (memory, SQLite), the envelope (tampered rows, a
  wrong name or revision in the AAD, rotation), the `ref+` parser and the allowlist, `azkv` against a
  fake Key Vault (`httptest`).
- tresor's conformance suite and the reference server's tests, with Keycloak, on memory and SQLite.
- Live, by hand (like tresor's `scripts/dev/entra_live.sh`), with the Entra tenant:
  - `scripts/dev/azure_live.sh`: a real Key Vault KEK and a `ref+azkv://` secret, used from DuckDB by
    an Entra person and an Entra node;
  - then the same against the Container Apps deployment.

## Alternatives considered

- **Delegations in SQLite now.** Not needed with one replica. It would mean sealing the minted
  tokens; phase 2 does it once, for all SQL stores.
- **Sealing each parameter apart** (spec 001's wording). One sealed document per secret is simpler
  and hides which parameters there are. No property is lost.
- **Resolving references at write.** It would copy material, or fail a write before the vault is
  ready. Resolution at fetch is what makes rotation work.
- **WAL on Azure Files.** WAL needs shared memory, which a network share does not give.
- **A conformance kit from tresor** (the `unittest` runner and tests as a release artifact): no C++
  build here. Better later; it needs a tresor release change first.

## Open questions

- **An Azure subscription** for Key Vault and Container Apps: is there one, and in which region?
  Without it, (d) and (e) are tested with fakes only.
- **The conformance runner**: a small hook in tresor's `scripts/ci/test_keycloak.sh`
  (`TRESOR_SERVER_CMD` and a config, instead of building `ref-server`), or a copy of the script here?
  The hook keeps one script; it is a tresor change, not a protocol one.
- **SQLite on Azure Files** (`journal: delete`, `nobrl`, one replica) as the recipe's default, or
  Azure SQL / PostgreSQL right away in phase 2?
- **The image registry**: `ghcr.io/hugr-lab/tresor-server`?

## Follow-ups

- `internal/policy` out of `internal/api`.
- OpenTelemetry traces and the audit (spec 001).
- Phase 2: PostgreSQL, SQL Server, delegations in the store, several replicas.
