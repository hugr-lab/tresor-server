---
title: Getting started
---

# Getting started

This page runs the service on a laptop, with SQLite and a local key, and attaches DuckDB to it.

## 1. An identity provider

The service verifies tokens from any OIDC issuer. Two ways to get one:

- **Keycloak in docker**, as tresor's own tests use it: `docker compose -p tresor-kc up -d` in tresor's
  `server/` (its `docker-compose.yml` and test realm). The issuer is then
  `http://127.0.0.1:18480/realms/tresor`.
- **Microsoft Entra ID**: register the service's API and the clients as tresor's
  [Entra guide](https://hugr-lab.github.io/tresor/entra/) says.

## 2. The service

Get the binary (`go build ./cmd/tresor-server`), or run the image
`ghcr.io/hugr-lab/tresor-server:edge`.

A configuration for the Keycloak above:

```yaml title="server.yaml"
listen: 127.0.0.1:8443
public_url: http://127.0.0.1:8443        # plain http only on this machine
state:
  kind: sqlite
  path: ./tresor.db
keys:
  kind: local
  key_env: TRESOR_KEK                    # 32 bytes, base64
issuers:
  - issuer: http://127.0.0.1:18480/realms/tresor
    audience: duckdb-secrets
    client_id: duckdb
    scopes: [openid]
    human_flows: [authorization_code, device_code]
    service_flows: [client_credentials]
    roles_claim: realm_access.roles
    service: {claim: client_id}
policy:
  admins: [role:secrets_admin]
```

```bash
export TRESOR_KEK="$(openssl rand -base64 32)"   # keep it: the database's material is sealed under it
./tresor-server -config server.yaml
```

The same settings can come from the environment instead of a file: see [Configuration](configuration.md).

The service answers:

- `GET /healthz`: the process is up.
- `GET /readyz`: the state store, the key and every issuer answer.
- `GET /.well-known/duckdb-secrets`: the protocol's discovery.

## 3. DuckDB

```sql
INSTALL tresor;   -- from your organisation's extension repository, or community once published
LOAD tresor;

ATTACH 'tresor:127.0.0.1:8443' AS corp (INSECURE_HTTP true);   -- a browser login
SELECT * FROM corp.whoami();
```

An administrator (a `secrets_admin` here) stores a secret, and grants its use to a role:

```sql
CREATE PERSISTENT SECRET lake IN corp (TYPE s3, KEY_ID 'AKIA...', SECRET '...', SCOPE 's3://lake');
CALL corp.grant_secret('lake', 'role:analysts', ['use']);
```

Anyone with the role then reads `s3://lake/...` with no secret of their own. tresor's
[getting started](https://hugr-lab.github.io/tresor/getting-started/) goes on from here: people and
services, servers acting for users, what DuckDB sees.

## Next

- [State stores](state.md): PostgreSQL or SQL Server, for several replicas.
- [Encryption](encryption.md): the key in Azure Key Vault instead of an environment variable.
- [Azure Container Apps](azure-container-apps.md): the service in Azure.
