# Spec 032: Snowflake - Iceberg through Horizon with generated tokens

- **Status**: accepted (the owner, 2026-10-25: "вживую, trial"; PAT, key pair and per-user)
- **Date**: 2026-10-25
- **Author**: hugr lab

## Summary

DuckDB 2.0's iceberg extension reads Snowflake-managed Iceberg tables through Snowflake's Horizon catalog
(Iceberg REST, `https://<account>.snowflakecomputing.com/polaris/api/catalog`) with vended storage
credentials. Its secret is `TYPE iceberg` with a bearer `TOKEN`. This spec makes that token a generated one
(spec 023), in the three ways Snowflake accepts: a PAT exchanged by the service, a key-pair JWT the service
signs, and a user's own token from the identity provider (External OAuth).

## Problem

- A PAT is exchanged at `/polaris/api/catalog/v1/oauth/tokens` with `grant_type=client_credentials`,
  `scope=session:role:<ROLE>` and the PAT as `client_secret` in the form, no client id.
  `oauth2_client_credentials` requires a `client_id` and sends the secret by HTTP Basic.
- A key-pair login sends a JWT Snowflake's way as `client_secret`: `iss` `<ACCOUNT>.<USER>.SHA256:<fp>`, `sub`
  `<ACCOUNT>.<USER>`, RS256. A `jwt` identity makes RFC 7523 client assertions only.
- Per user: Snowflake's External OAuth takes the IdP's token for the Snowflake resource (Entra, Okta or a
  custom issuer); the role comes from the token's scope (`session:role:<ROLE>`). This should already work
  with `mint+exchange` (spec 006, Entra OBO spec 013), but it was never run.

## Design

- **PAT**: `oauth2_client_credentials` with no `client_id`: the `client_secret` goes in the form
  (client_secret_post without an id). With a `client_id`, as now (HTTP Basic).
- **Key pair**: a new identity kind `snowflake` in `dynamic.identities`: `account`, `user`, `public_key_fp`
  (`SHA256:...`, as `DESC USER` shows it - a wrong one fails at Snowflake, never silently), `client`
  (`client_auth`: `key_file`, `keyvault`, `vault`, `awskms`, `gcpkms` - an RSA key), `token_urls`. A
  `jwt_assertion` login naming it sends its JWT (a minute's life) as `client_secret`, `grant_type`
  `client_credentials`, the login's `scope`.
- **Per user**: no code - `mint+exchange` (Entra On-Behalf-Of) for the Snowflake app's scope
  `session:role:<ROLE>`; Snowflake's External OAuth integration maps `upn` to `login_name`.
- **Docs**: a Snowflake recipe in Generated parameters: the iceberg secret (`TOKEN` generated, the catalog's
  URI), the `ATTACH` (`ACCESS_DELEGATION_MODE 'vended_credentials'` where needed), the three logins, the
  Snowflake side (the role, `session:role:`, PAT or `RSA_PUBLIC_KEY`, the External OAuth integration), and a
  token's life (an hour) against a long `ATTACH`.
- No protocol change: generated values are spec 023's.

## Enforcement & security

The PAT, the private key and users' tokens never leave the service; DuckDB gets an hour's bearer token for one
role. `token_urls` bound where a key's JWT goes; login hosts as for every login. Nothing logged but names.

## Testing

Done 2026-10-25 against the owner's Snowflake Enterprise trial (AWS), DuckDB 2.0.0 and tresor v0.1.0 (its CI
build), a tresor-server on this machine (`scripts/dev/snowflake_live.sh` for the Entra side):

- the PAT and the key pair: Horizon's token endpoint gives an hour's token for `session:role:TRESOR_READER`;
  Horizon lists the namespace, loads the table with vended S3 credentials; DuckDB `ATTACH … (TYPE iceberg,
  SECRET …, ACCESS_DELEGATION_MODE 'vended_credentials')` reads the rows, the token redacted;
- per user: the owner signed in to DuckDB (`LOGIN 'device'`, Entra); the service minted their Snowflake token by
  OBO (scp `session:role:TRESOR_READER`, upn); DuckDB read the table as `TRESOR_PERSON`;
- a reader of the secret needs `use` on the login as well (`403 mint_refused` otherwise) - see Follow-ups.

Planned:

- Go: the PAT form (no Basic, no client id), the Snowflake JWT's claims and signature, config refusals.
- **Live** (owner's Snowflake trial; `scripts/dev/snowflake_live.sh up|check|down`): a Snowflake-managed
  Iceberg table on Snowflake storage (`EXTERNAL_VOLUME = 'SNOWFLAKE_MANAGED'`, no cloud bucket), a role, a
  user with a PAT and an RSA key; a local tresor-server; DuckDB 2.0 with tresor reads the table through each
  login; per user with Entra (temporary tenant changes: an app for Snowflake, its scope, removed in `down`).
  `down` drops everything it made in the account.

## Alternatives considered

- Serving the PAT itself (`CLIENT_SECRET`, `OAUTH2_SERVER_URI`, `OAUTH2_SCOPE`) so iceberg exchanges and renews
  it: the PAT, a long-lived credential, would reach every client. Possible as a static secret today; not this.
- A `custom` (jq) login for the PAT: works today, but a PAT is common enough to be plain configuration.

## Follow-ups

- **`use` on the login** (the owner, 2026-10-25: noted, to be thought through - not changed now): a secret that
  generates from a service login (`mint+login://…`) is served only to a caller who holds `use` on the login as
  well as on the secret (else `403 mint_refused`). Two grants for one thing an administrator meant as one; to
  decide whether the secret's grant should carry the login's use (an admin wrote both), or the login be granted
  implicitly to the secret's readers, and what that means for per-user logins.

- iceberg renews a token only with its own OAuth2 client; a generated token past its hour fails a long
  `ATTACH` until it is attached again (checked live; if it bites, a tresor-side renewal).
