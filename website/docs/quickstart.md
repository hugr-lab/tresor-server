---
title: Quickstart
---

# Quickstart

Two ways to try tresor-server in your own infrastructure:

- **[The demo](#the-demo-five-minutes-with-keycloak)** - one `docker compose up` on a laptop or a VM: the service,
  Keycloak with a realm, people, a service and a sample secret. Five minutes, nothing to register.
- **[Your own identity provider](#your-own-identity-provider)** - one `docker run` against Entra ID or Keycloak,
  your people and roles.

Either way you are done when DuckDB answers:

```sql
INSTALL tresor FROM community;
LOAD tresor;
ATTACH 'tresor:<host>' AS corp;
FROM corp.whoami();
```

## The demo: five minutes with Keycloak

### What you need first

| What | Example | Notes |
| --- | --- | --- |
| Docker with Compose | Docker Desktop, or Docker Engine 24+ | `docker compose version` |
| Free ports on 127.0.0.1 | `8443` (the service), `18480` (Keycloak) | the demo listens on this machine's loopback only |
| DuckDB 2.0.0 | `duckdb` CLI, Python `duckdb==2.0.0` | tresor installs from DuckDB's community extensions |
| The repository | `git clone https://github.com/hugr-lab/tresor-server` | the recipe is `deploy/docker` |

The demo serves plain http on loopback, as the service allows only there: run DuckDB on the same machine. On a
VM, reach it through an SSH tunnel (`ssh -L 8443:127.0.0.1:8443 -L 18480:127.0.0.1:18480 <vm>`); for a host
other machines reach, use [your own identity provider](#your-own-identity-provider) or
[Docker on one host](docker.md#on-one-host), with TLS.

### Steps

```bash
cd tresor-server/deploy/docker
docker compose up -d                        # the service, Keycloak, a realm; the first run makes every password
docker compose --profile seed run --rm seed # a sample secret (s3, fake values) granted to the analysts
docker compose run --rm init passwords      # who signs in with what
```

- **anna** is an administrator (`secrets_admin`): she manages secrets and grants in the console,
  [http://127.0.0.1:8443/ui/](http://127.0.0.1:8443/ui/).
- **jonas** is an analyst (`analysts`): his DuckDB receives what is granted to the analysts.
- **etl** and **node** are services (client credentials).

Nothing is a default anyone else knows: the passwords, the KEK and the services' secrets are made on the first
run, in a Docker volume. `docker compose --profile seed down -v` removes everything.

### You're done when

DuckDB, signed in as jonas (a browser opens, or a device code is shown; Keycloak asks once to grant access to
`duckdb`):

```sql
INSTALL tresor FROM community;
LOAD tresor;
ATTACH 'tresor:127.0.0.1:8443' AS corp (INSECURE_HTTP true);
FROM corp.whoami();                 -- jonas, role:analysts
FROM corp.secrets();                -- lake, warehouse
FROM duckdb_secrets();              -- lake's secret value redacted
```

`INSECURE_HTTP` is for this loopback demo only. A service signs in with its client's credentials:

```sql
CREATE SECRET node_login (TYPE tresor, SCOPE 'tresor:127.0.0.1:8443', FLOW 'client_credentials',
  CLIENT_ID 'node', CLIENT_SECRET '<node's secret>', ISSUER 'http://127.0.0.1:18480/realms/tresor');
ATTACH 'tresor:127.0.0.1:8443' AS corp (INSECURE_HTTP true);
```

Then, in the console as anna: create a secret, grant it to `role:analysts`, and see it in jonas's
`corp.secrets()` ([the console](console.md)).

## Your own identity provider

One container, your identity provider, SQLite and a local key - a pilot for a team. For production, the same
service with its state in PostgreSQL and its key in a KMS: [Docker on one host](docker.md#on-one-host),
[Kubernetes](kubernetes.md), [Azure](azure-container-apps.md), [AWS](aws.md), [GCP](gcp.md).

### What you need first

| What | Example | Where to find it |
| --- | --- | --- |
| The issuer | `https://login.microsoftonline.com/<tenant>/v2.0`; `https://sso.corp.example/realms/corp` | Entra: the tenant id (Overview); Keycloak: the realm's URL |
| The service's API (its tokens' audience) | Entra: the API app's client id; Keycloak: `duckdb-secrets` | Entra: register an app for the service, *Expose an API* with a scope `access_as_user`, its manifest `requestedAccessTokenVersion: 2`. Keycloak: an audience mapper adding `duckdb-secrets` to the people's client's tokens |
| The people's public client | Entra: a public client app id; Keycloak: `duckdb` | a public client (no secret), redirect `http://127.0.0.1` (loopback, any port, for the CLI), device code allowed |
| Roles in the token | Entra: app roles - claim `roles`; Keycloak: realm roles - `realm_access.roles` | the role that makes an administrator, e.g. `secrets_admin` |
| How a service's token is told apart | Entra: `idtyp` equals `app`; Keycloak: the `client_id` claim | for services that use DuckDB too (client credentials) |
| The host name and TLS | `secrets.corp.example`, a certificate DuckDB trusts | a certificate and key in files, or TLS at a reverse proxy in front (`tls.offload`) |
| Where state lives | a SQLite file in a volume | PostgreSQL or SQL Server for several replicas: [State](state.md) |
| The key (KEK) | a 32-byte file for a pilot | a KMS for production: [Encryption](encryption.md) |
| A vault, optionally | `ref+vault://…`, `ref+azkv://…` | to leave values where they are: [References](references.md) |

tresor's [Entra guide](https://hugr-lab.com/docs/tresor/entra/) walks through the Entra registrations.

### Steps

```bash
mkdir tresor && cd tresor
openssl rand -base64 32 > kek                                  # back it up: the state is sealed under it
cp /path/to/secrets.corp.example.crt tls.crt && cp /path/to/secrets.corp.example.key tls.key
sudo chown 65532:65532 kek tls.key && sudo chmod 400 kek tls.key  # the service's user (nonroot) reads them, no one else
docker volume create tresor-state
docker run --rm -v tresor-state:/state alpine chown 65532 /state   # the service runs as nonroot

docker run -d --name tresor-server --restart unless-stopped -p 443:8443 \
  -v tresor-state:/var/lib/tresor -v "$PWD":/etc/tresor:ro \
  -e TRESOR_LISTEN=0.0.0.0:8443 \
  -e TRESOR_PUBLIC_URL=https://secrets.corp.example \
  -e TRESOR_TLS__CERT=/etc/tresor/tls.crt -e TRESOR_TLS__KEY=/etc/tresor/tls.key \
  -e TRESOR_STATE__KIND=sqlite -e TRESOR_STATE__PATH=/var/lib/tresor/tresor.db \
  -e TRESOR_KEYS__KIND=local -e TRESOR_KEYS__KEY_FILE=/etc/tresor/kek \
  -e TRESOR_ISSUERS="[{issuer: 'https://login.microsoftonline.com/<tenant>/v2.0', audience: '<api client id>',
      client_id: '<public client id>', scopes: [openid, offline_access, 'api://<api client id>/access_as_user'],
      human_flows: [authorization_code, device_code], service_flows: [client_credentials],
      roles_claim: roles, service: {claim: idtyp, equals: app, client_claim: azp}}]" \
  -e TRESOR_POLICY__ADMINS='[role:secrets_admin]' \
  ghcr.io/hugr-lab/tresor-server:v0.8.2
```

For Keycloak, the issuer is the realm's URL and:

```bash
  -e TRESOR_ISSUERS="[{issuer: 'https://sso.corp.example/realms/corp', audience: duckdb-secrets, client_id: duckdb,
      scopes: [openid], human_flows: [authorization_code, device_code], service_flows: [client_credentials],
      roles_claim: realm_access.roles, ignore_roles: [offline_access, uma_authorization, 'default-roles-*'],
      service: {claim: client_id}}]" \
```

- **Check it**: `curl https://secrets.corp.example/readyz` - every check `ok` (the state, the key, the issuer);
  `docker logs tresor-server` names a failing one, never a value.
- **A reverse proxy** in front (TLS there): `-e TRESOR_TLS__OFFLOAD=true`, no `TLS__CERT`/`TLS__KEY`, publish
  `-p 127.0.0.1:8080:8443` to the proxy only. [Docker on one host](docker.md#on-one-host) has one with Caddy.
- **Every setting** can come from the environment or a file: [Configuration](configuration.md).

### You're done when

```sql
INSTALL tresor FROM community;
LOAD tresor;
ATTACH 'tresor:secrets.corp.example' AS corp;   -- your company login
FROM corp.whoami();                            -- you, and your roles
```

An administrator then creates the first secret - in the [console](console.md) at
`https://secrets.corp.example/ui/`, or from DuckDB - and grants it to a role:

```sql
CREATE PERSISTENT SECRET lake IN corp (TYPE s3, KEY_ID 'AKIA…', SECRET '…', SCOPE 's3://lake');
CALL corp.grant_secret('lake', 'role:analysts', ['use']);
```
