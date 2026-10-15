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
| `${exchange://…}`, `${claim://…}` inside a string | the same, as a part of the string: `'Bearer ${exchange://crm-api}'`. |
| `mint++…` | a literal: one `+` dropped (`mint++x` is served as `mint+x`). Only lowercase `mint+` is read. |
| `$${` | a literal `${`. |

- **Where**: a parameter's whole string, a typed VARCHAR (`{"type": "VARCHAR", "value": …}`), and the strings
  inside a `MAP`, `STRUCT` or `LIST` (values, never keys).
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

## Refusals

- **At the write** (`422`), naming the parameter, never its value: a malformed generator, an unknown kind, an
  exchange for this service's own audience, a claim that names the session or binds a token (`sid`,
  `session_state`, `jti`, `nonce`, `at_hash`, `c_hash`, `s_hash`), `${` of a known kind with no closing `}`.
  `mint+login://` and `mint+rule://` are reserved for service logins (to come).
- **At the read**: `403 mint_refused` - the identity provider refused, the caller's token has no such claim
  (empty, a list or an object counts as none), or the claim is shaped like a token; `503` - the identity
  provider did not answer. Never an empty value.
- **Only administrators** write a generator, as any secret.
- **Material is a resolved copy**: never write it back - a served literal `mint+claim://sub` written back is a
  generator. The console shows what is stored (Admin → a secret's shape).

## `provider: token_exchange`

The older form (tresor specs/010) stays: an `http` (`bearer_token`) or `quack` (`token`) secret with
`provider: token_exchange` and `audience` (and `scope`) is served as if its token parameter were
`mint+exchange://<audience>?scope=<scope>` - since 0.5 **with provider `config`**, the consumer's. Rewriting
one in the new form changes nothing for its readers.

The service's client at the identity provider, for every exchange: [Token exchange](token-exchange.md).
