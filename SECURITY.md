# Security policy

## Reporting a vulnerability

Report it privately, through GitHub: **Security → Report a vulnerability** on this repository
(<https://github.com/hugr-lab/tresor-server/security/advisories/new>). Please do not open a public issue.

Say what is affected (the version, the state store, the KEK's kind), how to reproduce it, and what it exposes. We
answer within a week, agree on a fix and a date, and publish an advisory with the release that fixes it.

A vulnerability in the protocol `duckdb-secrets/1` or the DuckDB extension belongs to
[tresor](https://github.com/hugr-lab/tresor/security).

## In scope

- The service (`cmd/tresor-server`), its image `ghcr.io/hugr-lab/tresor-server` and its chart
  `oci://ghcr.io/hugr-lab/charts/tresor-server`.
- The deployment recipes in `deploy/` (Container Apps, Cloud Run, ECS) as published.
- Anything that breaks what [Security](https://hugr-lab.github.io/tresor-server/security) says the service
  guarantees: material, tokens, data keys or grant ids leaving the service; a value served that should be refused;
  a reference resolved outside its allowlist; a role managing what only an administrator may.

Not in scope: what that page says the service trusts (its identity providers, whoever can write its database or
holds the KEK, its administrators), and the scripts under `scripts/dev/`.

## Supported versions

The latest minor release gets security fixes: **0.4.x**. Before 1.0 a fix is not backported to an older minor;
upgrade ([Upgrading](https://hugr-lab.github.io/tresor-server/administration/upgrading)).

## Verifying a release

The image and the chart are signed keylessly by this repository's workflows (cosign), and the image carries an
SBOM and provenance: see [Verifying the artifacts](https://hugr-lab.github.io/tresor-server/security#verifying-the-artifacts).
