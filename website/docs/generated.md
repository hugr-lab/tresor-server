---
title: Generated parameters
---

# Generated parameters

A parameter of any secret type can be **made on each read** for the caller, instead of stored: a token minted
for them at their identity provider, or a claim of their token (spec 023, tresor spec 029). The secret keeps the
type and the provider its DuckDB extension reads - `http` + `config`, `azure` + `access_token`, `postgres` +
`config` - and DuckDB receives final values only.

```sql
-- a token for the caller, for the API's audience
CREATE PERSISTENT SECRET crm IN corp (TYPE http, SCOPE 'https://crm.corp.example',
  BEARER_TOKEN 'mint+exchange://crm-api');

-- Azure Blob through the azure extension: the caller's own Entra token (an exchange, or On-Behalf-Of)
CREATE PERSISTENT SECRET lake_blob IN corp (TYPE azure, PROVIDER access_token, ACCOUNT_NAME 'corplake',
  SCOPE 'az://corplake.blob.core.windows.net/',
  ACCESS_TOKEN 'mint+exchange://https://storage.azure.com/?scope=https://storage.azure.com/.default');

-- a header made of a claim, inside a MAP
CREATE PERSISTENT SECRET lake_api IN corp (TYPE http, SCOPE 'https://lake.corp.example',
  EXTRA_HTTP_HEADERS MAP {'X-User': 'user=${claim://preferred_username}'});
```

## The syntax

| Value | Made |
| --- | --- |
| `mint+exchange://<audience>[?scope=<scope>]` | a token for the caller at their identity provider (RFC 8693, or Entra On-Behalf-Of), for `<audience>`. The audience is everything up to the first `?`, percent-decoded; the query is `scope=` only. |
| `mint+claim://<claim>` | a top-level claim of the caller's verified token, as text: a string as it is, a number or a boolean as its JSON text. Never the token. |
| `mint+login://<login>#<field>` | a field of what a [service login](#service-logins) got: an access token, a session id. |
| `mint+login:scope#<field>` | the same, from the login bound to the caller, picked by the secret's scope ([per user](#per-user-logins)). |
| `${exchange://…}`, `${claim://…}`, `${login://…}`, `${login:scope#…}` inside a string | the same, as a part of the string: `'Bearer ${exchange://crm-api}'`. |
| `mint++…` | a literal: one `+` dropped (`mint++x` is served as `mint+x`), and the rest of that string is not read (no `${…}` in it). Only lowercase `mint+` is read. |
| `$${` | a literal `${`. |

- **Where**: a parameter's whole string, a typed VARCHAR (`{"type": "VARCHAR", "value": …}`), and the strings
  inside a `MAP`, `STRUCT` or `LIST` (values, never keys). Any other type (a BLOB, a number) is never read.
- **Shared with tresor's reference server**: the whole-value form `mint+…`. The reference server reads no
  `${…}` and keeps typed values literal: a store moved from it escapes its literal `${` as `$${` first.
- **Not in a reference**: a parameter that is a reference (`ref+…`) is read as it resolves - what a vault
  holds is never read as a generator.

## What is served

- **For whom**: the effective user - the caller, or under a delegation grant the grant's **user**, never the
  server ([Delegation](https://hugr-lab.github.io/tresor/protocol#delegation)). Under acl, the token or the
  claim is the person's, not the node's.
- **Dynamic**: the secret is `dynamic` (in a list too), and its material carries `expires_at`: the earliest
  expiry of what was made - a minted token's, a claim's token's (under a grant, the grant's) - less
  `dynamic.margin` (10 minutes by default, at most half of what is left). mssql renews a token 5 minutes before
  it expires: the margin has the client fetch a new one first.
- **Redacted**: every parameter holding a generated value is added to `redact_keys`: a token never shows in
  `duckdb_secrets()`.
- **The provider** served is the stored one - the consumer's.
- **Made once per read**: the same generator twice in a secret is one token.
- **Under a grant, the claims its secrets name**: a grant keeps, from its user's token, only the claims named by
  the secrets its server may use at the exchange. A secret granted later that names another claim is refused
  under that grant until a new session.

## Claims inside strings

A claim interpolated into a header, a connection string or a URL is text the user's identity provider gave:

- **A claim with a control character** (a line break, NUL) is never kept: a read that needs it is refused.
- **Prefer claims the user cannot change** (`sub`, an object id) to editable ones (`preferred_username`, where
  the IdP lets users edit it) for anything that grants access - in a connection string, `user=${claim://…}` is
  the database's login.
- **A value shaped like a token** (three parts joined by two dots, no space or `@`) is refused - a claim that
  carries a token is never served. A username such as `first.middle.last` is refused too: name another claim.

## Refusals

- **At the write** (`422`), naming the parameter, never its value: a malformed generator, an unknown kind, an
  exchange for this service's own audience, a claim that names the session or binds a token (`sid`,
  `session_state`, `jti`, `nonce`, `at_hash`, `c_hash`, `s_hash`), `${` of a known kind with no closing `}`.
  A login field that renews it (`refresh_token`) is never served. `mint+rule://` is reserved (to come).
- **At the read**: `403 mint_refused` - the identity provider refused, the caller's token has no such claim
  (empty, a list or an object counts as none), or the claim is shaped like a token; `503` - the identity
  provider did not answer. Never an empty value.
- **Only administrators** write a generator, as any secret.
- **Material is a resolved copy**: never write it back - a served literal `mint+claim://sub` written back is a
  generator. The console shows what is stored (Admin → a secret's shape).
- **A secret written before 0.5** is not dynamic, and makes nothing: a `mint+…` or `${exchange://…}` in it is
  served as stored until the secret is written again. A secret said static is never one made per caller.

## Service logins

A service that is no identity provider - its own login with a user and a password, an OAuth2 token endpoint, a
session id to send with every request - is logged in to by the service, which keeps the inputs and serves one
field of what it gets. A login is a secret of type `tresor_service_login`, written by an administrator, **never
served** (not listed on `/v1`, `404` on a read; the console lists them, `GET /admin/v1/logins`). Here, `crm_login`:

```json
{"type": "tresor_service_login", "provider": "config", "scope": ["https://crm.corp.example/api"],
 "params": {
   "flow": "custom",
   "username": "svc-duckdb", "password": "ref+azkv://corp-vault/crm-svc",
   "login_url": "/login",
   "login_request": "{login: $username, password: $password}",
   "login_response": "{session_id: .headers[\"x-session-id\"], refresh_token: .body.refresh, expires_in: .body.ttl}",
   "refresh_url": "/refresh",
   "refresh_request": "{refresh: $refresh_token}",
   "refresh_response": "{session_id: .headers[\"x-session-id\"], refresh_token: .body.refresh, expires_in: .body.ttl}"}}
```

```sql
CREATE PERSISTENT SECRET crm IN corp (TYPE http, SCOPE 'https://crm.corp.example/api/data',
  EXTRA_HTTP_HEADERS MAP {'X-Session-Id': '${login://crm_login#session_id}'});
```

| `flow` | Parameters | Fields |
| --- | --- | --- |
| `basic` | `username`, `password` | `authorization` (`Basic …`), no call |
| `oauth2_client_credentials` | `token_url`, `client_id`, `client_secret`, `scope` | the token response's: `access_token`, `token_type`, … |
| `oauth2_password` | `token_url`, `username`, `password`, `client_id` (`client_secret`), `scope` | the same |
| `custom` | `login_url`, `login_method` (POST), `login_request`, `login_response`, `content_type` (`json`, `form`); `refresh_url`, `refresh_method`, `refresh_request`, `refresh_response` | what `login_response` names |
| `oauth2_refresh` | `token_url`, `refresh_token` (the first one), `client_id` (`client_secret`), `scope` | the token response's |
| `jwt_assertion` | `token_url`, `identity` (a `jwt` one), `scope`, `grant` (`client_credentials`, or `jwt_bearer`) | the token response's |
| `rule` | `identity`, and what its kind asks: `scope` (azure, gcp), `endpoint`, `user`, `region` (aws_rds) | below |

- **The mappings are jq.** A login request's over the variables `$username`, `$password`, `$client_id`,
  `$client_secret`; a refresh request's over `$refresh_token`, `$client_id`, `$client_secret`; a response's over
  `{status, headers, cookies, body}` (header names lowercase, the body parsed when it is JSON) and
  `$refresh_token` only - a login never serves its own inputs back. The result names fields - any names - and
  `expires_in` (seconds) or `expires_at` (RFC 3339, Unix seconds or milliseconds); else `ttl` (a duration), else 10
  minutes. Whatever it says, a result is kept between 1 minute and 24 hours.
- **Where it calls**: a path is under the scope's first base URL; an absolute URL must be within the scope (no
  `.` or `..` segment, no encoded slash). Its host must be in `dynamic.login_hosts`; https (http only to this
  machine); a redirect is never followed; no proxy. It never connects to a link-local, unspecified or multicast
  address (a cloud's metadata endpoint), whatever the name resolves to. The allowlist trusts the names' DNS:
  list hosts whose DNS you control.
- **Where its fields go**: only to a secret whose scope is within the login's.
- **Renewal**: from `refresh_token` (an OAuth2 refresh, or the custom refresh) while the login has one - kept up
  to 12 hours past the result's expiry, and kept when a refresh gives no new one - else a new login; a refused
  refresh logs in again. What a login got is cached in each replica's memory until shortly
  before it expires; a restart logs in again.
- **Inputs**: `username`, `password`, `client_id`, `client_secret` may be references (`ref+…`),
  or hold the caller's claims (`mint+claim://preferred_username`, `${claim://…}` inside): one login for everybody,
  logged in per user. A reference may hold a claim too - `ref+vault://kv/users/${claim://sub}#password` - the
  claim a name or an id only (letters, digits, `.`, `_`, `@`, `-`, no `..`), the allowlist checked with it in. No
  other parameter takes a claim or a reference. The inputs are always redacted: the console's shape never shows
  them.
- **`oauth2_refresh`**: the refresh token an administrator wrote is spent at the first renewal; a rotated one is
  written back to the login (sealed, compare-and-set on its version - the login's version moves), so a restart
  and the other replicas renew from the latest. In one replica the renewals take turns. Two replicas renewing at
  the same moment may spend one token twice: with an IdP that revokes on reuse, prefer `client_credentials` or
  `jwt_assertion`, or one replica. It is written as it is - never a reference, never a claim.
- **Use**: a login is granted, as any secret, to roles and groups; a reader of a secret of the login holds `use`
  on both.
- **Bounds**: 10 seconds a call, 1 MiB a response, 100 ms a jq program. A refusal (4xx) is `403
  mint_refused`, an outage (5xx, no answer) `503`. Nothing a login sends or receives is logged: its name, the
  step and the status only.

### A key, a workload identity: `jwt_assertion` and rules

What gives the service's own power - a workload identity, a client's signing key - is the **operator's**,
in `dynamic.identities`, each bounded to what it may be asked for. A login names one; it never names a key
or an identity of its own. The identity's own rights bound the rest: give it only what its tokens are for.

```yaml
dynamic:
  login_hosts: [zitadel.corp.example]
  identities:
    - {name: catalog-sql, kind: azure, client_id: <a user-assigned identity>,
       scopes: [https://database.windows.net/.default], destinations: ['mssql://sql.corp.example']}
    - {name: catalog-cloudsql, kind: gcp, service_account: catalog@proj.iam.gserviceaccount.com,
       scopes: [https://www.googleapis.com/auth/sqlservice.login], destinations: ['postgres://catalog-cloudsql']}
    - {name: catalog-rds, kind: aws_rds, role_arn: arn:aws:iam::123456789012:role/catalog,
       endpoints: ['catalog.abc.eu-west-1.rds.amazonaws.com:5432'], users: [catalog],
       destinations: ['postgres://catalog.abc.eu-west-1.rds.amazonaws.com:5432']}
    - {name: lake-read, kind: aws_sts, role_arn: arn:aws:iam::123456789012:role/lake-read, duration: 1h,
       destinations: ['s3://lake']}
    - name: zitadel-etl                       # a ZITADEL machine user's key
      kind: jwt
      audience: https://zitadel.corp.example  # the assertion's aud: ZITADEL's issuer (default: the token endpoint)
      token_urls: [https://zitadel.corp.example/oauth/v2/token]
      client: {client_auth: key_file, key_file: /var/run/tresor/zitadel-etl.json}
```

| Kind | What it makes | Bounded by | Fields |
| --- | --- | --- | --- |
| `azure` | an Entra token of the service's identity, or of a user-assigned one (`client_id`) | `scopes`, `destinations` | `access_token` |
| `gcp` | an access token of the service's identity, or of a service account it impersonates (it holds Service Account Token Creator on it) | `scopes`, `destinations` | `access_token` |
| `aws_rds` | an RDS IAM token (15 minutes), with the service's identity or a role it assumes | `endpoints`, `users`, `destinations`; the region is `aws.region` | `password`, `user` |
| `aws_sts` | temporary credentials of a role it assumes (the session named `tresor-<login>`) | `role_arn`, `duration` (15m-12h; 1h at most when `aws.role_arn` chains roles), `destinations` | `access_key_id`, `secret_access_key`, `session_token` |
| `jwt` | a client's signed assertion (as `exchange.client_auth`: `keyvault`, `vault`, `awskms`, `gcpkms`, `key_file`) | `token_urls`: the only endpoints its assertions go to | used by `jwt_assertion` |

- **`destinations`**: a rule's login scope must be within them - where the credentials may go. A rule calls
  nothing; without this bound an administrator could send a database token anywhere.
- **The service's own identity** (azure with no `client_id`, gcp with no `service_account`) never mints a scope
  that opens its KEK or its secrets (`https://vault.azure.net/.default`, Managed HSM, `cloud-platform`,
  `cloudkms`): give a rule an identity of its own.

A rule's scope is where its fields go (`mssql://…`, `postgres://…`, `s3://…`): it calls nothing itself.
`mint+rule://<login>#<field>` is the same as `mint+login://…`.

```json
{"type": "tresor_service_login", "provider": "config", "scope": ["mssql://sql.corp.example"],
 "params": {"flow": "rule", "identity": "catalog-sql", "scope": "https://database.windows.net/.default"}}
```

```sql
-- mssql reads the token as its connection's login: no password anywhere. mssql finds an azure secret by its
-- name (AZURE_SECRET); the SCOPE is this service's bound, within the rule's destinations
CREATE PERSISTENT SECRET sales_token IN corp (TYPE azure, PROVIDER access_token, SCOPE 'mssql://sql.corp.example/sales',
  ACCESS_TOKEN 'mint+rule://catalog-sql-login#access_token');
ATTACH 'Server=sql.corp.example;Database=sales' AS sales (TYPE mssql, AZURE_SECRET 'sales_token');

-- PostgreSQL on RDS (its login, catalog-rds-login: {"flow": "rule", "identity": "catalog-rds",
--   "endpoint": "catalog.abc.eu-west-1.rds.amazonaws.com:5432", "user": "catalog"},
--   scope ["postgres://catalog.abc.eu-west-1.rds.amazonaws.com:5432"]): the database's login is the token.
-- postgres finds a secret by its name only (SECRET, or the name __default_postgres)
CREATE PERSISTENT SECRET catalog IN corp (TYPE postgres,
  SCOPE 'postgres://catalog.abc.eu-west-1.rds.amazonaws.com:5432/catalog',
  HOST 'catalog.abc.eu-west-1.rds.amazonaws.com', PORT 5432, DBNAME 'catalog', USER 'catalog',
  PASSWORD 'mint+rule://catalog-rds-login#password');
ATTACH '' AS catalog (TYPE postgres, SECRET catalog);
```

## Which extension reads what

A generated value reaches an extension when the extension looks the secret up through DuckDB (tresor's storage
is one of DuckDB's) - and stays fresh only as long as the extension reads it again. From their sources
(2026-10):

| Extension | Finds the secret | Reads it again |
| --- | --- | --- |
| httpfs (s3, gcs, r2, http), azure, delta, bigquery, gsheets | by type and scope | at each file or request: fresh |
| postgres, mysql, snowflake | by name only (`SECRET`, or `__default_<type>`); SCOPE ignored | the connection string is kept from ATTACH: a token that expires (RDS IAM: 15 minutes) fails new connections after it |
| mssql (hugr-lab) | by name (`SECRET`, `AZURE_SECRET`) | `AZURE_SECRET`: at each new connection near the token's expiry |
| iceberg REST | by name, or an unscoped `iceberg` secret | at ATTACH only; serve `token` and `endpoint`, without the client's credentials |
| airport, adbc_scanner | by type and scope (a named secret: in memory or a file only) | at ATTACH only |
| unity_catalog, keboola | by name in memory or a file only | - tresor's storage is not searched |
| motherduck, columnar adbc, http_client | not from a secret (a setting, the environment, the ATTACH string) | - |

- **bigquery** reads a secret of its own class: a secret from tresor's storage is refused today (tresor's client
  to fix).
- **Under acl**, a value made per user is the user's when the extension looks up with the session's context. A
  database ATTACH (mssql, postgres) is the instance's: one secret, resolved by the instance and pooled for every
  connection - by design. Per-user values are for what each request carries: http, quack, object storage.

**ZITADEL**: a machine user logs in with the JWT profile - its key signs, ZITADEL's issuer is the `aud`, the
assertion is the grant:

```json
{"type": "tresor_service_login", "provider": "config", "scope": ["https://zitadel.corp.example"],
 "params": {"flow": "jwt_assertion", "grant": "jwt_bearer", "identity": "zitadel-etl", "token_url": "/oauth/v2/token",
            "scope": "openid urn:zitadel:iam:org:project:id:<project>:aud"}}
```

An application's key (private_key_jwt) is `grant: client_credentials`, the default: the assertion authenticates the
client.

### Per-user logins

`subject` binds a login to one user (their `subject:<issuer>|<sub>`, as the console shows it). A secret's
`mint+login:scope#<field>` names no login: at each read the service takes the one bound to the **effective
user** - the caller, or under a delegation grant the grant's user - that the caller may use and whose scope
covers the secret's. User A through acl to service B: B sees A's login, never the node's. No login for the user,
or more than one: `403 mint_refused`; never another's, never one without `subject`.

## `provider: token_exchange`

The older form (tresor specs/010) stays: an `http` (`bearer_token`) or `quack` (`token`) secret with
`provider: token_exchange` and `audience` (and `scope`) is served as if its token parameter were
`mint+exchange://<audience>?scope=<scope>` - since 0.5 **with provider `config`**, the consumer's. Rewriting
one in the new form changes nothing for its readers.

The service's client at the identity provider, for every exchange: [Token exchange](token-exchange.md).
