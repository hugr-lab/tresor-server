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
| `tls.cert`, `tls.key` | The certificate to serve HTTPS with - read again when the files change (every 30 s; spec 029): a certificate renewed in place (cert-manager's Secret) is served without a restart. A new pair serves once it checks whole (the key the certificate's, the certificate in date); a bad one leaves the old pair serving, logs an error and makes readiness's `tls` degraded. |
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

An actor is a service: `client:<id>`, optionally pinned to its `issuer`; or, in this service (spec 031), a role,
`role:<name>`, with its `issuer` required and one of `issuers` - every service whose token from that issuer carries the role acts
for users with the rule's verbs: one rule for every node group of a platform, not one per client.

```yaml
policy:
  actors:
    - {principal: role:hugr_node, issuer: https://idp.example/realms/lake, verbs: [use]}
```

Only a service's token counts (a person given the role is no actor), and a rule naming the client wins over a
role's. A role is broader than a client id: whoever can give the role in the identity provider - to any of its
clients - lets that client act for every user. Give such a role to service accounts only, and keep the verbs to
`use` unless the nodes manage secrets for their users. A role rule is only as strong as the issuer's `service`
rule: name the claim's value (`equals`) where people's tokens could carry the claim too. A token with roles of
two rules gets the first rule's verbs, in the order listed. A grant stops working once its node's token no
longer carries the role; revoking by actor is per client.

For Microsoft Entra ID, see tresor's [Entra guide](https://hugr-lab.github.io/tresor/entra/).

Three settings of an issuer are this service's own (specs 026, 030):

| Setting | |
| --- | --- |
| `ignore_roles` | Roles of the roles claim never taken as principals - glob patterns: an identity provider's own, Keycloak's `offline_access`, `uma_authorization`, `default-roles-*`. They grant nothing anyway unless a grant or `policy.admins` names them; this keeps them out of `whoami` and the console. |
| `ca_file` | PEM certificates trusted for the issuer's discovery and keys, besides the system's - a cluster's own CA. |
| `discovery_token_file` | A bearer token sent (to the issuer's host, and its keys' host) to read its discovery and keys, read at each request - a Kubernetes API server serves them to authenticated accounts only. https issuers only. |

A cluster's own ServiceAccounts then log in with their projected tokens: [Kubernetes](kubernetes.md#the-clusters-own-accounts).

### `state`

Where the service keeps secrets, grants and delegation grants. See [State stores](state.md).

| Setting | |
| --- | --- |
| `state.kind` | `memory`, `sqlite`, `postgres`, `sqlserver` or `kubernetes`. Required. |
| `state.path` | SQLite: the database's file. |
| `state.dsn` | PostgreSQL, SQL Server: the server, the database, the user. Never a password. |
| `state.auth` | `entra` (the service's Azure token), `aws` (an RDS IAM token; [AWS](aws.md#the-database-rds-iam-authentication)) and `gcp` (Cloud SQL IAM; [GCP](gcp.md#the-database-cloud-sql-iam-database-authentication)) - PostgreSQL only -, `vault` (a database secrets engine's lease; [OpenBao and Vault](vault.md#the-databases-credentials)) or `password`. |
| `state.password_env`, `state.password_file`, `state.password_ref` | `auth: password`: where the password is - one of them. `password_ref` is `ref+k8s://…`, `ref+azkv://…`, `ref+vault://…`, `ref+aws://…`, `ref+gcp://…` or a named source's, outside every `material` allowlist (every source of its kind). |
| `state.vault` | `auth: vault`: `{mount, role, source, set_role}` - the engine's mount and role (`<mount>/creds/<role>`), a named vault source's connection (empty: `vault:`), and `set_role`, the group role every lease's user is granted: required on PostgreSQL, refused on SQL Server. |
| `state.max_open_conns` | The connection pool; default 10. |
| `state.mac` | SQL stores: check every row's MAC - who may use what cannot change without the KEK (spec 014). On by default since 0.4 (spec 022); `false` turns the checks off. See [State](state.md#the-sql-stores-mac-statemac). |
| `state.namespace` | Kubernetes: where the resources are. The pod's own by default; required outside a pod. |
| `state.instance` | Kubernetes: the installation's id, in every MAC. The namespace by default; keep it stable. |

### `keys`

The key-encryption key the material is sealed under. See [Encryption](encryption.md). Required for every
store but `memory`.

| Setting | |
| --- | --- |
| `keys.kind` | `local`, `azurekeyvault`, `vault`, `awskms` or `gcpkms`. |
| `keys.key_env`, `keys.key_file` | `local`: a 32-byte key, base64. |
| `keys.key` | `azurekeyvault`: `https://<vault>/keys/<name>`, with no version; `vault`: the Transit key's name. |
| `keys.mount` | `vault`: the Transit mount; default `transit`. |
| `keys.key`, `keys.mac_key` | `awskms`: two KMS keys' ARNs, a symmetric encryption key and an HMAC key. See [AWS](aws.md#the-kek-two-keys). `gcpkms`: a crypto key and a MAC key's version; see [GCP](gcp.md#the-kek-a-key-and-a-mac-version). |
| `keys.data_key_max_age` | A data key older than this is replaced for new values; default `720h`. |
| `keys.cache_ttl` | How long an unwrapped data key stays in memory; default `5m`. |
| `keys.previous` | KEKs data keys may still be under, read only, during a [move to another KEK](encryption.md#moving-to-another-kek): a list of `{kind, key_env, key_file, key, mount, mac_key}`. |

### `material`

Where references may read. See [References](references.md).

| Setting | |
| --- | --- |
| `material.azkv.allow` | `[{vault: corp-vault, prefixes: [lake-, duckdb-]}]`: the vaults, and the secret-name prefixes (none: all). |
| `material.azkv.cache_ttl` | Keep a value read for this long; default `0` (none), at most `5m`. |
| `material.azkv.dns_suffix` | Another cloud's Key Vault suffix; default `.vault.azure.net`. |
| `material.k8s.allow` | `[{namespace: data-team, prefixes: [duckdb-]}]`: the namespaces, and the Secret-name prefixes (none: all). |
| `material.vault.allow` | `[{mount: secret, prefixes: [duckdb/]}]`: the KV v2 mounts, and the path prefixes (none: all). Needs `vault:`. |
| `material.vault.cache_ttl` | Keep a value read for this long; default `0`, at most `5m`. |
| `material.aws.allow` | `[{prefixes: [duckdb/]}]`: Secrets Manager names' prefixes (an entry with none: all). Needs `aws.region`. |
| `material.aws.cache_ttl` | Keep a value read for this long; default `0`, at most `5m`. |
| `material.gcp.allow` | `[{project: corp-data, prefixes: [duckdb-]}]`: the projects (their ids, never numbers), and the secret-name prefixes (none: all). |
| `material.gcp.cache_ttl` | Keep a value read for this long; default `0`, at most `5m`. |
| `material.sources` | Named sources (spec 008): `[{name, kind: vault \| azkv \| aws \| gcp, vault: {…}, azure: {identity, client_id, tenant_id}, aws: {region, role_arn}, allow, cache_ttl, dns_suffix}]`. `ref+<name>://`. See [Named sources](references.md#named-sources). |

### `azure`

The service's own identity on Azure: for Key Vault, and for a database login by Entra token.

| Setting | |
| --- | --- |
| `azure.identity` | `managed` (a managed identity), `workload` (AKS workload identity: the pod's federated ServiceAccount token) or `default` (`DefaultAzureCredential`: the az CLI's login, for development). |
| `azure.client_id` | `managed`: a user-assigned identity's client id. `workload`: overrides the webhook's `AZURE_CLIENT_ID` - that identity needs a federated credential for this ServiceAccount (`system:serviceaccount:<ns>:<sa>`) and the cluster's issuer. |

`default` is for development. Its chain also takes a client secret from the environment
(`AZURE_CLIENT_SECRET`), which is a static secret. Production runs `managed` (Container Apps) or `workload` (AKS).

### `aws`

The service's own identity on AWS (spec 012): for KMS, Secrets Manager, RDS. See [AWS](aws.md).

| Setting | |
| --- | --- |
| `aws.region` | The region the service calls. Required when `aws` is used. |
| `aws.endpoint_url` | Another endpoint for every AWS API (a VPC endpoint, an emulator). |
| `aws.static_credentials` | `allow`: keys from the environment are admitted (development, tests); refused otherwise. |
| `aws.role_arn` | A role assumed with the service's identity (in a named source: another account). |

### `gcp`

The service's own identity on GCP (spec 012): Application Default Credentials. See [GCP](gcp.md).

| Setting | |
| --- | --- |
| `gcp.static_credentials` | `allow`: a service account key or a person's login is admitted (development, tests); refused otherwise. |

### `exchange` (per issuer)

The service's client at the issuer, for tokens minted for callers (`mint+exchange://`, `token_exchange` secrets). See
[Token exchange](token-exchange.md).

| Setting | |
| --- | --- |
| `client_id` | The service's client. With `key_file`, read from ZITADEL's key file when unset. |
| `client_auth` | `secret` (default), `azure`, `file`, `keyvault`, `key_file`, `vault`, `awskms` or `gcpkms`. |
| `client_secret_env` | `secret`: the variable holding the client secret. |
| `assertion_file` | `file`: a token read at each request (a projected ServiceAccount token). |
| `key`, `key_file` | `keyvault`: a Key Vault key URL. `vault`: a Transit key, `<mount>/<key>` (needs `vault`). `key_file`: ZITADEL's key file or a PEM key. `awskms`: an asymmetric KMS key's ARN (needs `aws`). `gcpkms`: an asymmetric key's version. |
| `kid`, `x5t` | What the JWT's header names the key by (`kid`; `x5t` for Entra's certificates). |
| `assertion_audience` | `issuer` (default) or `token_endpoint` (Entra). |
| `grant` | `token_exchange` (default; RFC 8693: Keycloak, ZITADEL) or `on_behalf_of` (Entra). See [Token exchange](token-exchange.md#entra-on-behalf-of-a-federated-credential). |
| `omit_client_id` | `file` only: leave `client_id` out of the request - Keycloak's federated client authentication refuses a `client_id` that is not the assertion's `sub`. `client_id` then names the client in the console only. |

**Roles from an object**: a `roles_claim` or `groups_claim` that is an object gives its keys (ZITADEL's
`urn:zitadel:iam:org:project:roles`). An issuer whose claim points at an object used to get nothing, and now
gets the keys: check the claim it names.

### `vault`

OpenBao or HashiCorp Vault (spec 007): the KEK in Transit (`keys.kind: vault`), `ref+vault`, `client_auth: vault`. See
[OpenBao and Vault](vault.md).

| Setting | |
| --- | --- |
| `vault.address` | `https://…` (http only to this machine). |
| `vault.namespace` | A namespace, when one is used. |
| `vault.ca_file` | A private CA; the system's roots otherwise. |
| `vault.auth.method` | `kubernetes`, `jwt` or `token_file`. |
| `vault.auth.mount`, `vault.auth.role` | The auth method's mount (default: the method's name), and the role. |
| `vault.auth.jwt_file` | `jwt`: the token to log in with. `kubernetes`: the pod's own by default. The chart's `vaultToken` sets it. |
| `vault.auth.token_file` | `token_file`: the token a Vault Agent writes, read again when it changes. |
| `keys.kind: vault`, `keys.key`, `keys.mount` | The Transit key, and its mount (default `transit`). |

### `ui`

The management console (spec 010) at `/ui/`, and its API at `/admin/v1`: administrators only. See
[Console](console.md).

| Setting | |
| --- | --- |
| `ui.enabled` | `true` (default: an upgrade serves the console with no change of configuration). `false`: no `/ui/`, no `/admin/v1`. |
| `ui.environment` | A label for the console's badge (`prod`, `staging`); unset, none. |
| `ui.allowed_origins` | The hosts that mount the console as a microfrontend (`https://platform.example`): CORS on `/ui/mfe/`, `/v1` and `/admin/v1`, for them only. |
| `ui.frame_ancestors` | Pages that may frame `/ui/`; none by default. |
| `ui.connect_src` | More origins the sign-in calls, for an IdP whose token or user-info endpoint is on another host than its issuer (Google: `https://oauth2.googleapis.com`; Entra: `https://graph.microsoft.com`). |

Origins are written as a browser sends them: `https://host[:port]`, no path, no default port, no wildcard.

People sign in with the issuers that have a `client_id`: register `<public_url>/ui/callback` as a redirect
URI of that client.

### `cors`

Web pages that run tresor in DuckDB-wasm call the service from the browser, across origins (tresor's protocol,
*Browsers*; spec 022).

| Setting | |
| --- | --- |
| `cors.allowed_origins` | The pages' origins (`https://notebook.example`): CORS on discovery (`/.well-known/duckdb-secrets`) and `/v1`, for them only. |

- The preflight allows the protocol's methods and the headers `Authorization`, `Content-Type`, `Accept`,
  `Delegation`, `If-Match`, `If-None-Match`, `traceparent`; answers expose `ETag` and `X-Request-Id`. No credentials: no cookie is
  sent or honoured, the bearer token is the only one.
- Separate from `ui.allowed_origins` (the console's hosts): neither list implies the other.
- An origin as a browser sends it: `https://host[:port]` (http only to this machine), no path, no wildcard.
- The page's sign-in is the IdP's: register the page's origin there too (a SPA client, CORS on its token endpoint).

### `dynamic`

[Generated parameters](generated.md) (spec 023).

| Setting | |
| --- | --- |
| `dynamic.login_hosts` | The hosts a [service login](generated.md#service-logins) may call: a name, or `*.domain`. Empty: no login calls out. |
| `dynamic.identities` | The workload identities and client keys a [rule or a `jwt_assertion`](generated.md#a-key-a-workload-identity-jwt_assertion-and-rules) may use: `name` (once each) and `kind`, and per kind: `azure` - `client_id`, `scopes`, `destinations`; `gcp` - `service_account`, `scopes`, `destinations`; `aws_rds` - `role_arn`, `endpoints`, `users`, `destinations`; `aws_sts` - `role_arn` (required), `duration` (15m-12h, default 1h), `destinations`; `jwt` - `client` (as `exchange`: `client_auth` `keyvault`, `vault`, `awskms`, `gcpkms` or `key_file`), `audience`, `token_urls`. Another kind's field is refused; every kind but `jwt` lists its `destinations`. |
| `dynamic.margin` | `expires_at` is this long before what was generated expires, at most half of what is left: up to `1h`; unset (or `0`), `10m`. |

### `audit`, `telemetry`

See [Observability](observability.md).

| Setting | |
| --- | --- |
| `audit.level` | `all` (default), `changes` (no successful read or inspection; a reveal is kept), or `off` (nothing). |
| `telemetry.traces` | `true` (default): spans under tresor's trace. `false`: the audit's `trace_id` only. |

OpenTelemetry's export uses its standard variables: `OTEL_EXPORTER_OTLP_ENDPOINT` (nothing is exported
without one), `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_SDK_DISABLED`.
