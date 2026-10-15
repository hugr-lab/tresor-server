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

-- Azure SQL through mssql: the caller's own Entra token (an exchange, or On-Behalf-Of: exchange.grant)
CREATE PERSISTENT SECRET sales_db IN corp (TYPE azure, PROVIDER access_token,
  ACCESS_TOKEN 'mint+exchange://https://database.windows.net/?scope=https://database.windows.net/.default');

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
- **Inputs**: `username`, `password`, `client_id`, `client_secret` may be references (`ref+…`), or hold the
  caller's claims (`mint+claim://preferred_username`, `${claim://…}` inside): one login for everybody, logged in
  per user. No other parameter takes a claim or a reference. The inputs are always redacted: the console's shape
  never shows them.
- **Use**: a login is granted, as any secret, to roles and groups; a reader of a secret of the login holds `use`
  on both.
- **Bounds**: 10 seconds a call, 1 MiB a response, 100 ms a jq program. A refusal (4xx) is `403
  mint_refused`, an outage (5xx, no answer) `503`. Nothing a login sends or receives is logged: its name, the
  step and the status only.

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
