---
title: Configuration
---

# Configuration

The configuration is YAML. It is read from three sources, each over the last:

1. **A file**: `tresor-server -config server.yaml`. Optional.
2. **`TRESOR_CONFIG`**: a whole YAML document in one environment variable.
3. **One variable per setting**: `TRESOR_` and the setting's path in capitals, `__` between the levels.

Unknown keys are errors, in a file and in the environment alike.

## From the environment

In a container, on Kubernetes or Container Apps, every setting can be an environment variable:

```bash
TRESOR_LISTEN=0.0.0.0:8080
TRESOR_PUBLIC_URL=https://secrets.corp.example
TRESOR_TLS__OFFLOAD=true
TRESOR_STATE__KIND=postgres
TRESOR_STATE__DSN='host=db.corp.example user=tresor dbname=tresor sslmode=verify-full'
TRESOR_STATE__AUTH=entra
TRESOR_KEYS__KIND=azurekeyvault
TRESOR_KEYS__KEY=https://corp-kv.vault.azure.net/keys/tresor-kek
TRESOR_AZURE__IDENTITY=managed
TRESOR_ISSUERS="[{issuer: 'https://login.microsoftonline.com/<tenant>/v2.0', audience: '<api client id>'}]"
TRESOR_POLICY__ADMINS='[role:secrets_admin]'
```

The rules:

- **Text** settings take the value as it is: a URL with `#`, a DSN, `null`.
- **Lists and sections** are read as YAML, so they fit in one variable (`TRESOR_ISSUERS`,
  `TRESOR_POLICY__ADMINS`).
- **A list is given whole.** Its items cannot be set one by one: `TRESOR_ISSUERS__0__ISSUER` is an error.
- **A section is set by its keys** (`TRESOR_STATE__KIND`); a whole document goes in `TRESOR_CONFIG`.
- **Typos are errors.** A `TRESOR_` variable shaped like a setting that names none (`TRESOR_STATE_KIND`,
  `TRESOR_POLICIES__ADMINS`) stops the service. Names are in capitals.
- **No weak typing.** A number where a text belongs is an error: `audience: 0123` must be quoted.
- **An empty variable** is an empty text: it clears what the file set.
- **Other `TRESOR_` variables are left alone**: the ones a `*_env` setting names, and tresor's test
  variables.
- **The log names the variables used**, never their values. No configuration error quotes a value.

Secrets are never in the configuration itself. A setting names where a secret is: `key_env`,
`password_env`, `client_secret_env`. Such a variable must not be a setting's own name.

## Settings

### `listen`, `public_url`, `tls`

| Setting | |
| --- | --- |
| `listen` | `host:port` to listen on. |
| `public_url` | The URL clients reach the service at; the discovery's `api`. It may have a path. |
| `tls.cert`, `tls.key` | The certificate to serve HTTPS with. |
| `tls.offload` | TLS ends at the platform's ingress (Container Apps, an ingress controller). |

Plain http is allowed only on a loopback address, unless `tls.offload` is set. With it:

- the service listens with plain http on any address;
- `public_url` must be `https`;
- the port must be reachable **only** through the ingress.

### `issuers`, `policy`

These are the reference server's, unchanged. tresor documents them:

- [`issuers`](https://hugr-lab.github.io/tresor/reference-server/): the identity providers - issuer,
  audience, the public client, the flows, the roles and groups claims, how a service's token is told apart
  from a person's, and the client the service mints tokens for callers with (`exchange`).
- [`policy`](https://hugr-lab.github.io/tresor/reference-server/): `admins` (who manages secrets and grants
  their use) and `actors` (the servers allowed to act for users, and with which verbs).

For Microsoft Entra ID, see tresor's [Entra guide](https://hugr-lab.github.io/tresor/entra/).

### `state`

Where the service keeps secrets, grants and delegation grants. See [State stores](state.md).

| Setting | |
| --- | --- |
| `state.kind` | `memory`, `sqlite`, `postgres`, `sqlserver` or `kubernetes`. Required. |
| `state.path` | SQLite: the database's file. |
| `state.dsn` | PostgreSQL, SQL Server: the server, the database, the user. Never a password. |
| `state.auth` | `entra` (the service's Azure token) or `password`. |
| `state.password_env`, `state.password_file`, `state.password_ref` | `auth: password`: where the password is - one of them. `password_ref` is `ref+k8s://…` or `ref+azkv://…`, outside every `material` allowlist. |
| `state.max_open_conns` | The connection pool; default 10. |
| `state.namespace` | Kubernetes: where the resources are. The pod's own by default; required outside a pod. |
| `state.instance` | Kubernetes: the installation's id, in every MAC. The namespace by default; keep it stable. |

### `keys`

The key-encryption key the material is sealed under. See [Encryption](encryption.md). Required for every
store but `memory`.

| Setting | |
| --- | --- |
| `keys.kind` | `local` or `azurekeyvault`. |
| `keys.key_env`, `keys.key_file` | `local`: a 32-byte key, base64. |
| `keys.key` | `azurekeyvault`: `https://<vault>/keys/<name>`, with no version. |
| `keys.data_key_max_age` | A data key older than this is replaced for new values; default `720h`. |
| `keys.cache_ttl` | How long an unwrapped data key stays in memory; default `5m`. |

### `material`

Where references may read. See [References](references.md).

| Setting | |
| --- | --- |
| `material.azkv.allow` | `[{vault: corp-vault, prefixes: [lake-, duckdb-]}]`: the vaults, and the secret-name prefixes (none: all). |
| `material.azkv.cache_ttl` | Keep a value read for this long; default `0` (none), at most `5m`. |
| `material.azkv.dns_suffix` | Another cloud's Key Vault suffix; default `.vault.azure.net`. |
| `material.k8s.allow` | `[{namespace: data-team, prefixes: [duckdb-]}]`: the namespaces, and the Secret-name prefixes (none: all). |

### `azure`

The service's own identity on Azure: for Key Vault, and for a database login by Entra token.

| Setting | |
| --- | --- |
| `azure.identity` | `managed` (a managed identity), `workload` (AKS workload identity: the pod's federated ServiceAccount token) or `default` (`DefaultAzureCredential`: the az CLI's login, for development). |
| `azure.client_id` | `managed`: a user-assigned identity's client id. `workload`: overrides the webhook's `AZURE_CLIENT_ID` - that identity needs a federated credential for this ServiceAccount (`system:serviceaccount:<ns>:<sa>`) and the cluster's issuer. |

`default` is for development. Its chain also takes a client secret from the environment
(`AZURE_CLIENT_SECRET`), which is a static secret. Production runs `managed` (Container Apps) or `workload` (AKS).

### `audit`, `telemetry`

See [Observability](observability.md).

| Setting | |
| --- | --- |
| `audit.level` | `all` (default), `changes` (no successful read), or `off`. |
| `telemetry.traces` | `true` (default): spans under tresor's trace. `false`: the audit's `trace_id` only. |

OpenTelemetry's export uses its standard variables: `OTEL_EXPORTER_OTLP_ENDPOINT` (nothing is exported
without one), `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_SDK_DISABLED`.
