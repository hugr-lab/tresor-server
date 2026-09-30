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

Go 1.26, no cgo.

```bash
go test ./...                                   # the Go tests (GOWORK=off inside a go.work tree)
go build -o tresor-server ./cmd/tresor-server
./tresor-server -config server.yaml             # the reference server's config, plus state:
```

- `/healthz`: the process is up. `/readyz`: the state store and every issuer answer.
- tresor's conformance suite runs against this service through tresor's `scripts/ci/test_keycloak.sh`:

  ```bash
  scripts/ci/tresor_checkout.sh ../tresor-pin --submodules   # tresor at the pinned commit; build it (make)
  scripts/ci/conformance.sh ../tresor-pin memory             # needs docker: Keycloak
  ```

  Any tresor checkout at the pinned commit with its `build/release` works.

Parts of the code started as tresor's reference server (MIT, the same owner): see [NOTICE](NOTICE).

## License

Business Source License 1.1 - see [LICENSE](LICENSE). Production use is permitted, embedding included,
except as a hosted or managed service offered to third parties; each version becomes Apache-2.0 four
years after its release. The parameters (Additional Use Grant, Change Date, Change License) are the
licensor's and may be revised before the first release.
