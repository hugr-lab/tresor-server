---
title: Docker
---

# Docker

`deploy/docker` runs the service with Docker Compose, two ways: **to try it** on this machine with Keycloak, and
**on one host** behind Caddy, with your identity provider.

## To try it

The service and Keycloak, a realm with people and services, and sample secrets - the console and DuckDB work at
once. Not for production: Keycloak runs `start-dev`, and the KEK is a file in a volume.

```bash
cd deploy/docker
docker compose up -d                          # the first run makes the KEK, passwords, realm and configuration
docker compose run --rm init passwords        # who signs in with what
docker compose --profile seed up seed         # optional: sample secrets, grants and a variable
open http://127.0.0.1:8443/ui/                # the console
```

- **Nothing is a default**: the first run makes the KEK, every password and the services' secrets, in the
  volume `tresor_data`; `init passwords` shows them. `docker compose --profile seed down -v` deletes them with the state.
- **Who is there**: `anna` (`secrets_admin`: manages secrets and grants), `jonas` (`analysts`: uses what is
  granted); the services `etl` (an administrator) and `node` (role `nodes`, which may act for users -
  [an actor by role](configuration.md)).
- **The seed**: `lake` (s3) and `warehouse` (postgres) with fake values, and the variable `lake_bucket`, all
  granted to `role:analysts`; `lake` to `role:nodes` too.
- **Loopback only**: the service allows plain http on a loopback address only. It listens on 127.0.0.1 inside
  the network namespace of a small bridge (socat), which publishes it on this machine's 127.0.0.1:8443 and
  forwards 127.0.0.1:18480 to Keycloak: the issuer, `http://127.0.0.1:18480/realms/tresor`, is the same URL
  for the browser, DuckDB and the service.
- **A build of your own**: `docker build -t tresor-server:local .` at the repository's root, then
  `TRESOR_IMAGE=tresor-server:local docker compose up -d`.

From DuckDB:

```sql
INSTALL tresor FROM community; LOAD tresor;
ATTACH 'tresor:127.0.0.1:8443' AS corp (INSECURE_HTTP true);   -- a browser or a device-code sign-in
SELECT * FROM corp.secrets();
```

A service signs in with its client's credentials (`node`'s secret from `init passwords`):

```sql
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:127.0.0.1:8443', FLOW 'client_credentials',
  CLIENT_ID 'node', CLIENT_SECRET '…', ISSUER 'http://127.0.0.1:18480/realms/tresor');
```

## On one host

`compose.host.yaml`: Caddy terminates TLS with a certificate from Let's Encrypt for your domain and forwards to
the service (`tls.offload`); your identity provider; SQLite in a volume, or PostgreSQL.

```bash
cd deploy/docker
cp host/server.example.yaml host/server.yaml     # your domain, issuer and admins
mkdir -m 700 host/secrets
openssl rand -base64 32 > host/secrets/kek && chmod 644 host/secrets/kek
echo TRESOR_DOMAIN=secrets.example.com > .env
docker compose -f compose.host.yaml up -d
```

- **DNS and ports**: the domain points at the host; ports 80 and 443 are open (Let's Encrypt's HTTP challenge,
  then HTTPS). The service has no published port: Caddy is the way in.
- **The KEK** is a file on the host, handed in as a Compose secret: **back it up** apart from the state - the
  state is sealed under it, and nothing in it opens without it. Where the host has a KMS or Vault, use it
  instead ([Encryption](encryption.md)); the file is for a host with no identity.
- **The secrets' directory** is the host's to keep closed (0700); its files are read in the containers by their
  own users (the service runs as nonroot, PostgreSQL as `postgres`), hence 0644.
- **PostgreSQL**: `openssl rand -hex 24 > host/secrets/pg-password && chmod 644 host/secrets/pg-password`, the
  state as in `server.example.yaml`'s comment, and `docker compose -f compose.host.yaml --profile postgres up -d`.
- **Backups**: the state volume (SQLite: `tresor-host_state`; PostgreSQL: `pg_dump`) and the KEK -
  [Backup and restore](administration/backup-restore.md).
- **Upgrading**: set `TRESOR_IMAGE` (or the default tag in `compose.host.yaml`) to the new version and
  `docker compose -f compose.host.yaml up -d`; read [Upgrading](administration/upgrading.md) first.
