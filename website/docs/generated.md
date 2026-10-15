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
  `mint+login://` and `mint+rule://` are reserved for service logins (to come).
- **At the read**: `403 mint_refused` - the identity provider refused, the caller's token has no such claim
  (empty, a list or an object counts as none), or the claim is shaped like a token; `503` - the identity
  provider did not answer. Never an empty value.
- **Only administrators** write a generator, as any secret.
- **Material is a resolved copy**: never write it back - a served literal `mint+claim://sub` written back is a
  generator. The console shows what is stored (Admin → a secret's shape).
- **A secret written before 0.5** is not dynamic, and makes nothing: a `mint+…` or `${exchange://…}` in it is
  served as stored until the secret is written again. A secret said static is never one made per caller.

## `provider: token_exchange`

The older form (tresor specs/010) stays: an `http` (`bearer_token`) or `quack` (`token`) secret with
`provider: token_exchange` and `audience` (and `scope`) is served as if its token parameter were
`mint+exchange://<audience>?scope=<scope>` - since 0.5 **with provider `config`**, the consumer's. Rewriting
one in the new form changes nothing for its readers.

The service's client at the identity provider, for every exchange: [Token exchange](token-exchange.md).
