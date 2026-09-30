# tresor-server

The production [`duckdb-secrets/1`](https://github.com/hugr-lab/tresor/blob/main/website/docs/protocol.md)
service behind [tresor](https://github.com/hugr-lab/tresor), the DuckDB extension:
`ATTACH 'tresor:secrets.corp.example' AS corp` logs DuckDB in through the organization's OIDC provider,
and the secrets the caller's roles may use become part of DuckDB's own secret lookup.

- **State** in SQLite, PostgreSQL, SQL Server or Kubernetes - several replicas where the store allows.
- **Material** encrypted under a KMS key (Azure Key Vault first), or left where the organization keeps it
  (Azure Key Vault Secrets first) and referenced.
- **No static passwords**: managed identities, database logins through Entra ID or IAM.
- **One container**; Azure Container Apps first, then Kubernetes (Helm).

Status: phase 1 in progress - see [spec 001](specs/001-architecture/spec.md) (the architecture) and
[spec 002](specs/002-phase1-azure-mvp/spec.md) (phase 1, the Azure MVP).

## Develop

Go 1.27, no cgo.

```bash
go test ./...                                   # the Go tests (GOWORK=off inside a go.work tree)
go build -o tresor-server ./cmd/tresor-server
./tresor-server -config server.yaml             # the reference server's config, plus state:
TRESOR_LISTEN=127.0.0.1:8443 TRESOR_STATE__KIND=memory ... ./tresor-server   # or all from the environment
```

Every setting can come from the environment, over the file: `TRESOR_CONFIG` (a whole YAML document) or
`TRESOR_<PATH>` per setting, `__` between levels, the value read as YAML (`TRESOR_POLICY__ADMINS=[role:admins]`).

- State: `memory`, or `sqlite` (one replica), its params sealed under a KEK (AES-256-GCM, data keys wrapped by
  the KEK):

  ```yaml
  state: {kind: sqlite, path: /data/tresor.db}
  keys: {kind: local, key_env: TRESOR_KEK}      # 32 bytes, base64: openssl rand -base64 32
  # or PostgreSQL, several replicas; the password (or an Entra token) is never in the DSN:
  # state: {kind: postgres, dsn: 'host=db user=tresor dbname=tresor sslmode=verify-full', auth: entra}
  # or SQL Server / Azure SQL, with an Entra access token (no password at all):
  # state: {kind: sqlserver, dsn: 'sqlserver://corp.database.windows.net?database=tresor&encrypt=true', auth: entra}
  # or a key in Azure Key Vault / Managed HSM, with the service's managed identity:
  # keys: {kind: azurekeyvault, key: https://corp-kv.vault.azure.net/keys/tresor-kek}
  # azure: {identity: managed}                  # default: the az CLI's login, for development
  ```

  After a rotation of the KEK, `tresor-server rewrap -config …` moves the data keys to its current version.

- Material that stays in Azure Key Vault: an administrator writes a parameter as a reference,
  `ref+azkv://<vault>/<secret>[/<version>]` (from DuckDB: `CREATE PERSISTENT SECRET … (SECRET 'ref+azkv://corp-vault/lake-s3') IN corp`).
  It is read at each fetch with the service's identity (Key Vault Secrets User), only within the allowlist:

  ```yaml
  material:
    azkv:
      allow: [{vault: corp-vault, prefixes: [lake-, duckdb-]}]
  ```
  `scripts/dev/azure_live.sh up` checks the Key Vault KEK against a real vault.

- `/healthz`: the process is up. `/readyz`: the state store, the KEK and every issuer answer.
- tresor's conformance suite runs against this service through tresor's `scripts/ci/test_keycloak.sh`:

  ```bash
  scripts/ci/tresor_checkout.sh ../tresor-pin --submodules   # tresor at the pinned commit; build it (make)
  scripts/ci/conformance.sh ../tresor-pin sqlite             # memory | sqlite; needs docker: Keycloak
  ```

  Any tresor checkout at the pinned commit with its `build/release` works.

Parts of the code started as tresor's reference server (MIT, the same owner): see [NOTICE](NOTICE).

## License

Business Source License 1.1 - see [LICENSE](LICENSE). Production use is permitted, embedding included,
except as a hosted or managed service offered to third parties; each version becomes Apache-2.0 four
years after its release. The parameters (Additional Use Grant, Change Date, Change License) are the
licensor's and may be revised before the first release.
