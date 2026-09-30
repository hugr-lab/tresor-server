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

Status: design - see [specs/001-architecture](specs/001-architecture/spec.md).

## License

Business Source License 1.1 - see [LICENSE](LICENSE). Production use is permitted, embedding included,
except as a hosted or managed service offered to third parties; each version becomes Apache-2.0 four
years after its release. The parameters (Additional Use Grant, Change Date, Change License) are the
licensor's and may be revised before the first release.
