# Spec 023: dynamic parameters - any secret type, a value made on each read

- **Status**: draft (waits for tresor spec 029)
- **Date**: 2026-10-15
- **Author**: hugr lab

## Summary

Today a dynamic secret is one shape: `provider: token_exchange`, a token for the caller, in `http.bearer_token`
or `quack.token` only. This spec makes it abstract (the owner, 2026-10-15, agreed with tresor): **any parameter
of any type** may be made on each read - a token for the caller, a claim of the caller's token, or a value from
a **service login** the service keeps (a login and refresh with a password, OAuth2, OIDC, a JWT assertion, a
session id, a custom flow). The secret keeps its consumer's type and provider (`azure` + `access_token` for
mssql, `postgres` + `config`), and the service serves final values. tresor spec 029 adds the protocol's note
(the provider is the consumer's; generated values, whole or inside a string; generated keys always redacted) and
`exchange` and `claim` in tresor's reference server; this spec is tresor-server's side, `login` and `rule` its
own.

## Problem

- A token in another type needs code: a new entry in `tokenParam` (internal/api/minted.go:37) per type.
- The served provider is `token_exchange`; tresor puts it into DuckDB as the secret's provider, and a consumer
  that checks its provider refuses it (mssql's `TYPE azure` needs `PROVIDER access_token`).
- A service that is not an identity provider - its own `/login` and `/refresh`, a session id to send in a
  header - cannot be used at all without a password in a secret, served to every caller, never renewed.
- Through acl (a delegation grant), service B should see user A, not acl's server user: today only an IdP's
  exchange can do that.

## Design

### Generated values

A parameter's VARCHAR value - whole, or a part of it - names how it is made on each read. The syntax is shared
with tresor's reference server and is not the protocol's (as `ref+` is not):

| Form | Value |
| --- | --- |
| `mint+exchange://<audience>[?scope=<scope>]` | a token for the effective user (RFC 8693, or Entra OBO by `exchange.grant`) - today's `token_exchange` |
| `mint+claim://<claim>` | a claim of the caller's verified token (`sub`, `preferred_username`, `upn`, `email`, …); never the token |
| `mint+login://<login>#<field>` | a field of a service login's result (below) |
| `mint+login:scope#<field>` | the same, the login picked by the secret's scope for the effective user (per-user logins) |
| `${<form without mint+>}` inside a string | the same, interpolated: `'Session ${login://portal#session_id}'`; `$${` is a literal `${` |

- Inside MAP, STRUCT and LIST values too (`EXTRA_HTTP_HEADERS MAP {'X-Session': '${login://portal#session_id}'}`).
- A secret with any generated value is **dynamic**: `dynamic: true`, `expires_at` = the earliest expiry of its
  values minus a margin (`dynamic.margin`, default 10 minutes: mssql renews 5 minutes before a token's `exp`).
  A value with no expiry (a claim) does not shorten it; a secret of claims only expires after `dynamic.claim_ttl`
  (default 5 minutes).
- **Generated keys are always in `redact_keys`** (tresor spec 029).
- **The provider served is the stored one** - the consumer's. `provider: token_exchange` stays readable as an
  alias: such a secret is served as before; `tresor-server migrate-dynamic` (or the console) rewrites one into
  `provider: config` + `mint+exchange://` in its token parameter.
- **The effective user**: the caller reading directly; under a delegation grant, the grant's user - never the
  server (protocol).

### Service logins (`tresor_service_login`)

A login is a secret of type `tresor_service_login` (tresor spec 029's name; `tresor_login` is spec 025's human
login there). It is **never served by `/v1`** - not listed, `404` on `GET` - only its descriptor and shape through
`/admin/v1` and the console; an admin writes it with `PUT /v1/secrets/{name}` (and, once tresor registers the type,
with `CREATE SECRET`). Its params:

```yaml
type: tresor_service_login
scope: [https://crm.example]          # the only base URLs it may call, and where its results may be used
params:
  flow: custom                        # basic | oauth2_password | oauth2_client_credentials | oauth2_refresh
                                      # | jwt_assertion | session | custom
  username: svc-duckdb
  password: ref+azkv://corp-vault/crm-svc     # a reference, or sealed as any secret's param
  login_url: /login
  login_request: '{login: $username, password: $password}'        # jq, over the inputs
  login_response: '{access_token: .body.accessToken, refresh_token: .body.refreshToken, expires_in: 3600}'
  refresh_url: /refresh
  refresh_request: '{refreshToken: $refresh_token}'
  refresh_response: '{access_token: .body.accessToken, refresh_token: .body.refreshToken, expires_in: 3600}'
  subject: null                       # per user: the user's subject (below)
```

- **Flows**: `basic` (a field `authorization` = `Basic base64(user:password)`, no call), `oauth2_password`,
  `oauth2_client_credentials` (RFC 6749, `token_url`, `scope`, client auth as `exchange.client_auth`),
  `oauth2_refresh` (a stored refresh token: the first is written by the admin), `jwt_assertion` (RFC 7523, the
  key in a KMS or Transit, as exchange's `client_auth`), `session` and `custom` (any request and response, by jq -
  hugr query-engine's `x-hugr-token-transform`, `x-hugr-refresh-transform`).
- **The response** is read as `{status, headers, cookies, body}`; the mapping yields named fields - any names
  (`access_token`, `session_id`, `cookie`, …) and `expires_in` (seconds) or `expires_at`. Without either:
  `ttl` from the login's params, else 10 minutes.
- **Renewal**: the refresh call when the login has one and holds a refresh value; otherwise a new login. A
  refresh refused (`400`/`401`) falls back to a new login once. Single-flight per login and user.
- **Kept inside**: refresh tokens, cookies, passwords and every field a secret does not name never leave the
  service. Results are cached in memory per replica, per login and effective user, until their expiry minus the
  margin; nothing new is persisted (a restart logs in again).
- **Bounds**:
  - URLs only within the login's `scope` and the operator's `dynamic.login_hosts` (https; http on loopback);
    redirects not followed;
  - a 10 s limit per call, 1 MiB per response, 100 ms per jq program;
  - no response body, header or field value in a log or an error - the status and the login's name only.

### Per-user logins

`use` is granted only to roles and groups (tresor spec 029, item 6) - logins too. A login for one user is bound
by its **`subject` param**, written by the admin (the user's subject, as the console shows it):

- `mint+login:scope#<field>`: at each read, the service takes the logins whose scope matches the secret's, whose
  grants hold the effective user's roles, and whose `subject` is the effective user's; one - used; none -
  `403 mint_refused` ("no service login for the caller"), never a fallback to a login without `subject`;
  several - `403 mint_refused` (ambiguous).
- Or one login for everybody, its inputs interpolated: `username: ${claim://preferred_username}`,
  `password: ref+vault://kv/users/${claim://sub}#password` - a reference resolved within the allowlist after
  interpolation.

### Rules (`mint+rule://`)

A rule is a login with a workload identity instead of a password: `flow: azure | gcp | aws_rds | aws_sts`, the
identity (the service's own, or one in `dynamic.identities`: a user-assigned identity's client id, a GCP service
account to impersonate, an AWS role to assume), and the resource (an Entra scope, an RDS host/port/user/region).
Fields: `access_token`, `password` (RDS), `access_key_id`/`secret_access_key`/`session_token` (STS). A rule is a
`tresor_service_login` too: `mint+login://` names it; `mint+rule://` is the same form.

### Configuration

```yaml
dynamic:
  margin: 10m                  # expires_at = the earliest expiry minus this
  claim_ttl: 5m
  login_hosts: [crm.example, "*.corp.example"]   # empty: no login may call out
  identities:                  # workload identities a rule may use besides the service's own
    - {kind: azure, client_id: 0000…}
    - {kind: gcp, service_account: catalog@proj.iam.gserviceaccount.com}
    - {kind: aws, role_arn: arn:aws:iam::123456789012:role/catalog}
```

### Where it lives

- `internal/mint`: the generators (exchange - today's code, claim, login, rule) and the interpolation walk over
  typed params; gojq for the transforms.
- `internal/api/minted.go`: the token_exchange path becomes the `exchange` generator; `tokenParam` goes (kept for
  the alias).
- No state migration: a login is a secret; `subject` is a param.

## Enforcement & security

- **Admins manage, roles use**: only an admin writes a generated value, a login or a rule; a login is never
  served; an identity outside `dynamic.identities` and a host outside `dynamic.login_hosts` are refused at the
  write and again at each read.
- **Fail closed**: a value that cannot be made fails the read - `403 mint_refused` (a refusal: the login's
  credentials, no login for the user) or `503` (an outage) - never an empty value, never a stale one past its
  expiry.
- **Never the server's for a user**: under a grant, every caller-bound value is the grant's user's.
- **No SSRF**: the host allowlist, no redirects, https; a login's scope bounds both where it calls and which
  secrets may use it (a secret whose scope is outside the login's scope is refused at the write).
- **Nothing sensitive logged**: values, responses, cookies, refresh tokens - never; errors name the login and
  the step.
- **Across versions**: a 0.4 replica serves a `mint+` value as written (a literal string): roll out every replica
  before writing one; the console warns while replicas differ.

## Testing

- Go: each flow against an httptest server (login, refresh, a refused refresh, a session id from a header, a
  cookie, expiry handling), the interpolation walk (MAP, STRUCT, LIST, `$${`), the per-user pick (one, none,
  several), the alias, the bounds (host, redirect, size, time, jq).
- The state suite unchanged (a login is a secret); the API's tests: a login never on `/v1`, redact_keys.
- tresor's conformance at the spec 029 pin: `exchange` and `claim` on every store.
- End to end: a secret with `mint+login` read through tresor in DuckDB (`http` with `extra_http_headers`); an
  `azure` + `access_token` secret read by mssql-extension (with duckdb-acl).

## Alternatives considered

- **A provider per type** (today): code for every type, and the consumer's provider lost.
- **A `tresor_dynamic` type served to DuckDB**: no extension reads it; the consumer's type must stay.
- **Granting a login to a user**: `use` is for roles and groups (tresor); the `subject` param binds instead.
- **Persisting login results** (shared by replicas): fewer logins, but refresh tokens and cookies at rest -
  later, sealed, if a service limits sessions.

## Follow-ups

- tresor registers `tresor_service_login` in DuckDB (CREATE SECRET for logins).
- Persisted, sealed login results (services with a session limit).
- A keep-alive call per login.
