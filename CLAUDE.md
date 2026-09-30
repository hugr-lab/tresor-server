# tresor-server — Development Guidelines

tresor-server is the production `duckdb-secrets/1` service behind tresor (the DuckDB extension,
`~/projects/hugr-lab/tresor`). The protocol is normative in tresor: `website/docs/protocol.md`.
Read **[specs/001-architecture/spec.md](specs/001-architecture/spec.md)** first.

## Technology

- **Go** (one module, `github.com/hugr-lab/tresor-server`); one binary, `cmd/tresor-server`, in a
  distroless image. No cgo (SQLite through `modernc.org/sqlite`).
- **State**: SQLite, PostgreSQL (`pgx`), SQL Server (`go-mssqldb`), Kubernetes (CRD).
- **Azure**: `azidentity`, Key Vault keys (KEK) and secrets (material references).
- **License**: BUSL 1.1 (as acl-otel). Code taken from tresor's reference server (MIT) says so in
  its commit.

## Key rules

- **The protocol is tresor's.** A change to requests or responses lands in tresor's `protocol.md`
  first; tresor's conformance suite runs here against every state store.
- **Never** log or emit material, tokens, data keys or delegation ids; errors name what, never the value.
- **Fail closed**: a KEK or a reference that does not resolve is an error, never an empty value.
- **Admins manage, roles use** (tresor specs/009); references are written by admins only, and
  resolved only within the configured allowlist.
- **No static secrets for the service itself** where the platform has an identity.
- Every write to state is compare-and-set on the version.

## Working process

One lightweight spec per change under `specs/` (see [specs/README.md](specs/README.md)). Changes go
through a branch, a PR and a review; do not push without being asked. `design/` is local and gitignored.
