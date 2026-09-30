# tresor-server on Azure Container Apps

`main.bicep` deploys tresor-server with several replicas, and no password or secret of the service's own.

What it creates in a resource group:

- **A user-assigned managed identity.** Everything the service reaches, it reaches as this identity.
- **A Key Vault** on the RBAC permission model, with purge protection. It holds:
  - the KEK, an RSA-3072 key `tresor-kek`. The identity is *Key Vault Crypto Service Encryption User* on that
    key only (get, wrap, unwrap);
  - the secrets that references (`ref+azkv://`) may read. The identity is *Key Vault Secrets User* on the vault.
- **The database**, Entra authentication only, with the identity as its administrator:
  - `database=postgres`: Azure Database for PostgreSQL Flexible Server, Burstable B1ms;
  - `database=sqlserver`: Azure SQL, a serverless database that pauses when idle.
- **A Container Apps environment** with a Log Analytics workspace, and the app:
  - built-in ingress with TLS (`tls.offload`: TLS ends at the ingress);
  - two replicas or more;
  - liveness `/healthz` and readiness `/readyz`.

The configuration is all environment variables (`TRESOR_*`). Nothing is mounted.

## Deploy

```bash
az group create -n tresor -l westeurope
az deployment group create -g tresor -f main.bicep \
  -p database=postgres \
  -p issuers="[{issuer: 'https://login.microsoftonline.com/<tenant>/v2.0', audience: 'api://tresor', client_id: '<public client>', human_flows: [authorization_code, device_code], service_flows: [client_credentials], roles_claim: roles, service: {claim: idtyp, equals: app}}]" \
  -p admins="[role:secrets_admin]"
```

The outputs are the service's URL (`https://…azurecontainerapps.io`), the vault's name, and the identity's client
id. DuckDB then attaches it:

```sql
ATTACH 'tresor:<url without https://>' AS corp;
```

What the issuers take is tresor's [Entra ID](https://github.com/hugr-lab/tresor/blob/main/website/docs/entra.md)
guide: the app registration, its audience, the roles.

Parameters:

| Parameter | Default | |
| --- | --- | --- |
| `database` | `postgres` | `postgres` or `sqlserver` |
| `issuers` | - | `TRESOR_ISSUERS`: the identity providers (YAML) |
| `admins` | - | `TRESOR_POLICY__ADMINS`: who manages secrets (YAML list of principals) |
| `actors` | `[]` | `TRESOR_POLICY__ACTORS`: the servers that act for users (duckdb-acl nodes) |
| `materialAllow` | this vault, names `duckdb-*` | `TRESOR_MATERIAL__AZKV__ALLOW`: where references may read |
| `image` | `ghcr.io/hugr-lab/tresor-server:edge` | pin a release tag in production |
| `minReplicas`, `maxReplicas` | 2, 3 | |

## For production

The recipe is small on purpose. Tighten it:

- **Network.** The database and the vault take connections from Azure services (`AllowAzureServices`).
  Put the environment in a VNet, and reach the database and the vault through private endpoints.
- **The database's administrator.** The identity is the server's Entra administrator, so no database user needs
  making by hand. A tighter setup:
  1. an administrator of your own;
  2. a role for the identity that owns only the `tresor` database. On PostgreSQL:
     `SELECT * FROM pgaadauth_create_principal('<identity name>', false, false);` then
     `GRANT ALL ON DATABASE tresor TO "<identity name>"`. On Azure SQL:
     `CREATE USER [<identity name>] FROM EXTERNAL PROVIDER; ALTER ROLE db_owner ADD MEMBER [<identity name>];`
- **References to other vaults.** For each vault in `materialAllow`, give the identity *Key Vault Secrets
  User* on the vault, or on the secrets it may read.
- **The KEK.** Rotate it in the vault (a rotation policy), then run `tresor-server rewrap` (a Container Apps
  job with the same image and settings) so the old versions can be retired.
- **The image.** Pin a version tag, not `edge`.
- **Minted secrets** (`token_exchange`) need the service's own client at the IdP. Its secret goes in as a
  Container Apps secret, referenced by the environment variable the issuer's `exchange.client_secret_env` names.
