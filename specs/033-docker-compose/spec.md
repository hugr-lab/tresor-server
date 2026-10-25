# Spec 033: a Docker recipe

- **Status**: accepted (the owner, 2026-10-25: "compose: tresor + Keycloak")
- **Date**: 2026-10-25
- **Author**: hugr lab

## Summary

`deploy/docker`: tresor-server with Docker Compose, two ways. **Try it**: the service and Keycloak on this
machine, one command, a realm with an administrator, an analyst and services, and sample secrets - the
console and DuckDB work against it at once. **One host**: the service behind Caddy (automatic HTTPS for your
domain), your identity provider, SQLite or PostgreSQL.

## Design

- **Try it** (`compose.yaml`):
  - an `init` step makes, on the first run only, into `./data` (files 0600): the KEK, the users' and
    services' passwords, the realm and the service's configuration - nothing is a default anyone else knows;
    `./data/passwords.txt` is for whoever runs it;
  - Keycloak (`start-dev`, the realm imported) at `http://127.0.0.1:18480`; the service at
    `http://127.0.0.1:8443`, published on loopback only;
  - plain http needs a loopback listen address (the service's own rule): the service listens on its
    container's 127.0.0.1, and a small bridge in its network namespace (socat) forwards the published port to
    it and 127.0.0.1:18480 to Keycloak - the issuer is the same URL for the browser and the service;
  - `seed` (optional profile): sample secrets, grants, a variable and a login, made as a service admin.
- **One host** (`compose.host.yaml`): Caddy terminating TLS (`caddy reverse-proxy`, Let's Encrypt for
  `TRESOR_DOMAIN`), the service with `tls.offload` and no published port; `host/server.yaml` from an example
  (issuer, admins, domain); SQLite in a volume (made the service's by an init step), or PostgreSQL (a profile);
  the KEK a file on the host handed in as a Compose secret - Vault or a KMS where the host has one.
- The image's tag is a variable (default: the release); a local build for development.
- Docs: a Docker page (both ways, backup of `./data`, upgrading); Getting started points to it.

## Enforcement & security

The try-it stand listens on loopback only and makes its own secrets; it is not for production (start-dev
Keycloak, a KEK on disk) and says so. The host recipe keeps the service's rules: TLS, no default secrets.

## Testing

CI (`scripts/ci/docker.sh`, job "Docker recipes"): the try-it stand from the commit's image - ready, seeded, the
`node` service reads `lake` (granted to its role) and not `warehouse`, the console answers; the one-host recipe
on `localhost` - Caddy's own CA, discovery through it names `https://localhost`. Both were also run by hand, and
the console was walked through on the stand.
