# Spec 001: tresor-server — a duckdb-secrets/1 service for the enterprise

- **Status**: accepted
- **Date**: 2026-09-30
- **Author**: hugr lab

## Summary

tresor-server is the production service behind tresor, the DuckDB extension:
- it speaks the open protocol `duckdb-secrets/1`;
- it verifies the callers' tokens from any OIDC issuer (Entra ID, Keycloak, Okta, Auth0);
- it applies one policy: administrators manage, roles use;
- it serves each caller the secrets their roles may use.

What it adds over tresor's reference server:
- state in a real database (SQLite, PostgreSQL, SQL Server, Kubernetes), with several replicas where
  the database allows;
- material encrypted under a key held in a KMS (Azure Key Vault Keys first);
- material that stays where the organization already keeps it (Azure Key Vault Secrets first),
  referenced rather than copied;
- a container to deploy, Azure Container Apps first.

It is licensed under BUSL 1.1, like acl-otel:
- production use is free, embedding included;
- offering it to third parties as a hosted or managed service needs a commercial license;
- each version becomes Apache-2.0 four years after its release.

## Problem

tresor's reference server (`tresor/server`, MIT) proves the protocol and runs the conformance
suite. It is not meant for production:
- one process, one encrypted file, no replicas;
- the key comes from an environment variable;
- material is always copied into its file.

An organization that adopts tresor needs:
- **a highly available service** in its cloud, with no static passwords: managed identities, and
  database logins through Entra or IAM;
- **its existing vaults**: the S3 key already rotated in Azure Key Vault should serve DuckDB
  without being copied, and a rotation there should reach DuckDB with no action;
- **its own database**: PostgreSQL in one company, SQL Server in another, SQLite for a small
  install or a laptop.

## Design

### The product and tresor

- **The protocol stays in tresor.** `tresor/website/docs/protocol.md` is normative. A protocol
  change lands there first and here second.
- **Conformance.** This repository's CI runs tresor's conformance suite (`test/sql/conformance`)
  against this service, with every state store. That is how two implementations of the protocol
  stay one protocol.
- **Where the code starts.** The API layer is an internal package of this application, not a
  shared library. It starts as a copy of the reference server's `internal/{api,auth,config,mint}`,
  at a pinned tresor commit (MIT, the same owner), and diverges from there. The reference server
  stays small.
- **The binary's name.** tresor's reference binary was also `cmd/tresor-server`. It is renamed
  there to `ref-server` (a small tresor PR), so the two are never confused.

### Layers

```text
cmd/tresor-server          the binary: config, wiring, /healthz, /readyz
internal/api               duckdb-secrets/1 routes (discovery, whoami, secrets, grants, delegations, mint)
internal/auth              token verification (JWKS), principals, the service rule
internal/policy            admins manage, roles use; actors (duckdb-acl nodes) and their verbs
internal/state             StateStore + sqlite | postgres | sqlserver | kubernetes
internal/keys              KeyWrapper + local | azurekeyvault   (later: awskms, gcpkms)
internal/material          MaterialSource + inline | azurekeyvault | kubernetes   (later: awssm, gcpsm, vault)
internal/audit             the audit log, OpenTelemetry
```

### The interfaces

```go
// StateStore keeps what the service knows about secrets. Every write is compare-and-set on version.
type StateStore interface {
	List(ctx context.Context) ([]Secret, error)
	Get(ctx context.Context, name string) (Secret, error)                      // ErrNotFound
	Create(ctx context.Context, s Secret) (Secret, error)                      // ErrExists
	Update(ctx context.Context, name string, version int64, fn func(*Secret) error) (Secret, error) // ErrConflict
	Delete(ctx context.Context, name string, version int64) error
	Delegations() DelegationStore                                               // grants to act for a user, with expiry
	DataKeys() DataKeyStore                                                     // wrapped data keys, by id
	Close() error
}

// KeyWrapper wraps data keys under a key-encryption key the service never holds.
type KeyWrapper interface {
	Wrap(ctx context.Context, dek []byte) (wrapped []byte, keyID string, err error)
	Unwrap(ctx context.Context, wrapped []byte, keyID string) ([]byte, error)
}

// MaterialSource reads a value the organization keeps elsewhere, with the service's own identity.
type MaterialSource interface {
	Scheme() string                                   // "azkv", "k8s", ...
	Resolve(ctx context.Context, ref Ref) (value []byte, version string, err error)
}
```

### State in SQL: three dialects

One schema, and one set of queries written for the portable subset:

| Table | Holds |
| --- | --- |
| `secrets` | name, type, provider, scope (JSON as text), comment, owner, version, created/updated, the material (ciphertext, the data key's id) or its references |
| `grants` | secret, principal, verbs |
| `delegations` | id (hashed), actor, subject, issuer, verbs, expires_at |
| `data_keys` | id, wrapped key, KEK id, created, retired |

- **Compare-and-set**: `UPDATE … WHERE name = ? AND version = ?`, then the rows affected. It is the
  same in all three databases, and it is what makes several replicas safe.
- **Portability:**
  - no upsert: `INSERT`, and the unique violation mapped to `ErrExists`;
  - JSON kept as text;
  - the dialects differ in placeholders (`$1`, `@p1`, `?`), column types and the DDL of the
    migrations, which are embedded SQL files per dialect.
- **SQLite** (`modernc.org/sqlite`, pure Go: no cgo, a distroless image, every platform):
  - one replica, WAL mode;
  - small installs, development, a laptop.
- **PostgreSQL** (`pgx`): several replicas. On Azure Database for PostgreSQL the password is an Entra
  token (`BeforeConnect`); on RDS an IAM token.
- **SQL Server / Azure SQL** (`go-mssqldb`): several replicas. On Azure SQL, Entra authentication
  (managed identity, `DefaultAzureCredential`), with no password at all.
- **A password, where one is needed**, comes from a MaterialSource (Key Vault, a Kubernetes Secret,
  a file). It is read again for each new connection: a rotation needs no restart.

### State in Kubernetes

- A `TresorSecret` CRD per secret, in the service's namespace. Compare-and-set through
  `resourceVersion`, so several replicas need no database.
- Grants and delegations live in its status or in sibling resources. To be settled in its own spec.
- Material is never in the CRD: it is inline ciphertext, or a reference.

### Material: inline, or a reference

- **Inline**: what `CREATE PERSISTENT SECRET … IN corp` writes.
  - Each parameter is encrypted with AES-256-GCM under a data key; the AAD is the secret's name and
    version.
  - The data key is wrapped by the KeyWrapper.
  - Unwrapped data keys are cached in memory for a short time.
- **A reference**: a parameter's value names where the value lives, for example
  `ref+azkv://corp-vault/lake-s3-secret`. A `ref+` prefix in the value, as helm-secrets and vals
  write it: no protocol change.
  - It is resolved at each fetch, with the service's identity. A rotation in the vault reaches
    DuckDB at its next fetch.
  - A reference is written only by an administrator.
  - It is resolved only within the configured allowlist (vaults, name prefixes). Otherwise an
    administrator could make the service read any secret its identity can reach.
  - A parameter written as a literal that happens to start with `ref+` is refused, never guessed at.
- **Dynamic material** (minted per caller, tresor specs/010) stays as the reference server does it.

### The KEK

- **local**: a 32-byte key from a file or an environment variable, for development and SQLite.
- **azurekeyvault**: an RSA or AES key in Key Vault or Managed HSM (wrapKey/unwrapKey), with the
  service's managed identity (`Key Vault Crypto User`).
- **Rotation**: a new data key is used for new writes. Old ones are rewrapped under the new KEK
  version, with no need to re-encrypt material.

### Deployment

One Go binary in a distroless image, stateless where the state store allows. It is served over
HTTPS: tresor requires https.

| Where | How | State |
| --- | --- | --- |
| **Azure Container Apps** (first) | a managed identity for Key Vault and the database; built-in ingress with TLS; VNet and private endpoints to Key Vault and the database | SQLite on Azure Files (one replica), or Azure SQL / PostgreSQL (several) |
| **AKS / any Kubernetes** | Helm: Deployment, Service, Ingress, PodDisruptionBudget; workload identity | the CRD store, or a database |
| **A VM, docker compose** | small installs | SQLite |

- The configuration is the reference server's YAML plus `state:`, `keys:` and `material:`.
- `/readyz` is ready only when the state store, the KEK and every issuer's JWKS answer.
- The audit goes to OpenTelemetry; on Azure, to Log Analytics through the collector.

### Phases

1. **The Azure MVP:**
   - the API layer taken over from the reference server;
   - SQLite;
   - a local or Azure Key Vault KEK;
   - Azure Key Vault references;
   - the container and the Container Apps recipe;
   - tresor's conformance suite green.
2. **PostgreSQL and SQL Server**: one SQL layer, two more dialects, database logins through Entra.
   Several replicas.
3. **Kubernetes**: the Helm chart, the CRD store, Kubernetes Secrets as a material source,
   workload identity.
4. **AWS and GCP** (Secrets Manager and KMS), then HashiCorp Vault.

Each phase gets its own spec here.

## Enforcement & security

- **Fail closed:**
  - a KEK that does not unwrap, or a reference that does not resolve, is an error for that fetch,
    never an empty or stale value;
  - an unreachable state store is 503;
  - `/readyz` goes unready.
- **Nothing sensitive leaves the service** except material, to a caller allowed to `use` it. That
  means no material, token, data key or delegation id in a log, in the audit or in an error.
- **References** are an administrator's, within the allowlist; the audit records each resolution
  (name, source, version; never the value).
- **The service's identity** is a managed identity or workload identity wherever the platform has
  one. Database and KMS logins use no static secrets.
- **Replicas** only on a store with compare-and-set (PostgreSQL, SQL Server, Kubernetes). SQLite
  refuses to start when it finds another writer.

## Testing

- One test suite for `StateStore`, run against:
  - SQLite, in process;
  - PostgreSQL and SQL Server, in containers in CI (testcontainers; `mcr.microsoft.com/mssql/server`,
    `azure-sql-edge` on arm64).
- `KeyWrapper` and `MaterialSource` with fakes, and a live Azure script (like tresor's
  `scripts/dev/entra_live.sh`) against a real Key Vault.
- tresor's conformance suite and Keycloak end to end in CI, with each state store.
- A live Azure run per phase: Entra people and nodes, Key Vault, Container Apps.

## Alternatives considered

- **An open shared library** for the protocol layer, used by both the reference server and this
  one. Rejected: the product owns its API layer, and the conformance suite keeps the two in line.
- **Key Vault as the state store**, one Key Vault secret per DuckDB secret. Rejected:
  - it has no compare-and-set, so one replica only;
  - soft delete keeps a dropped name taken;
  - there are request limits.

  Key Vault is the KEK and a material source instead.
- **DuckDB as the embedded database.** Its Go driver needs cgo, and the state is transactional
  (OLTP), not analytical. SQLite fits; DuckDB can come later if wanted.

## Decisions (2026-09-30)

- **The reference syntax**: a `ref+` prefix in the parameter's value. A descriptor field would
  change `protocol.md` for what is the service's own business.
- **The docs**: a site of its own, as tresor, duckdb-acl and acl-otel have.
- **The repository**: public from the start (`hugr-lab/tresor-server`).

## Open questions

- **Grants and delegations in the CRD store**: status, or sibling resources (phase 3's spec).
