# Spec 036: a quickstart and a README that says what it is

- **Status**: accepted (the owner, 2026-10-29: "подтверждаю" - the tasks after the public release)
- **Date**: 2026-10-29
- **Author**: hugr lab

## Summary

After the public release people land on the repository and the docs. The README now says what tresor-server is,
how it works and how to deploy it, and a Quickstart page gets them to a working `whoami` from DuckDB in their own
infrastructure - with a demo, or with their own identity provider.

## Design

- **Quickstart** (`website/docs/quickstart.md`, second in the sidebar; https://hugr-lab.com/docs/tresor-server/quickstart/,
  linked from tresor's README):
  - **the demo**: what you need first (Docker, the loopback ports, DuckDB 2.0.0), the Docker recipe of spec 033
    (`compose up`, the seed, `init passwords`), done when DuckDB signs in as an analyst (`INSTALL tresor FROM
    community`) and sees the granted secrets, redacted; on a VM, an SSH tunnel (the demo is loopback only);
  - **your own identity provider**: a checklist (item, example, where to find it - the issuer, the service's API and
    audience in Entra or Keycloak, the people's public client and its loopback redirect, the roles claim and the admin
    role, how a service's token is told apart, the host and TLS or a reverse proxy, the state, the KEK, a vault), one
    `docker run` from the environment (Entra; the Keycloak issuer as a variant), file ownership for the nonroot user,
    `readyz`, done when `whoami` answers.
- **README**: the pitch, the pain, what it does, a mermaid diagram (DuckDB+tresor - IdP and tresor-server - state,
  KMS, vault), "Try it in 5 minutes", deploy targets as a table, development and the license in short. Every link
  to the site and the docs goes to hugr-lab.com; GitHub links only for repositories, releases and CI (the owner, as
  tresor#85). duckdb-acl is not named (not released).
- **Repository metadata** (done, the owner's yes): description, homepage https://hugr-lab.com/tresor, topics.

## Testing

- The demo end to end (2026-10-29): the released image v0.8.1, DuckDB 2.0.0, `INSTALL tresor FROM community`
  (v0.1.1), jonas signed in by device code (Keycloak asks once to grant access): `whoami` role:analysts,
  `corp.secrets()` lake and warehouse, `duckdb_secrets()` redacted.
- Your own IdP: the page's `docker run` verbatim against the owner's Entra tenant (v0.8.1, a self-signed
  certificate for localhost): `readyz` ok for the state, the key, the Entra issuer and TLS; an Entra service token's
  `whoami` answered (role:nodes).
- The docs build (links throw); the README's hugr-lab.com links answer (Quickstart once released).
