# Spec 017: the service's own client refused by the IdP - the service's problem, not the caller's

- **Status**: implemented
- **Date**: 2026-10-08
- **Author**: hugr lab

## Summary

When the identity provider refuses the service's own client (`invalid_client`, `unauthorized_client`) during a
token exchange, an operator's mistake (a federated credential missing, a secret rotated, the exchange permission
not given) is reported today as the IdP refusing the caller: `403 mint_refused`. Under a delegation grant it is
worse: the refusal is stored in the grant, and the grant stays refused for its whole life, after the operator has
fixed the configuration. This makes it what it is: `503 service_unavailable`, never stored, logged as an error.

## Problem

`internal/mint` sorts an IdP's answer into a refusal (an error code, a 4xx) or an outage (no answer, a 5xx);
`internal/api` answers a refusal with 403 and keeps it in the grant's minted token (`failed`), and an outage with
503, kept nowhere, tried again at the next read. An error code about the client itself is sorted as a refusal:

- **Entra**: `invalid_client` for a client secret that is wrong or expired (AADSTS7000215, 7000222) and for a
  federated credential that does not match the managed identity (AADSTS70021); `unauthorized_client` for an app
  that is not found or disabled in the tenant (AADSTS700016, 7000112).
- **Keycloak**: `invalid_client` for a wrong secret or a client assertion it does not accept; `unauthorized_client`
  for a client that may not exchange tokens (the token-exchange permission).
- **ZITADEL**: `invalid_client` for a key or an assertion it does not accept.

Each says nothing about the user; each is fixed by the operator, after which every grant should work again.
(The service's own failure to make its assertion - the platform's identity endpoint down - is already an
outage: `client_auth`, 503.)

## Design

- `mint.Error.ClientRefused()`: the code is `invalid_client` or `unauthorized_client`. Such an error is neither a
  refusal nor transient in the old sense: the API treats it as an outage of the service's own configuration.
- **The answer**: `503 service_unavailable`, detail "the identity provider does not accept the service's own
  client (its configuration)", on every path that exchanges: directly for the caller, at a grant's lazy mint, at a
  grant's refresh. The IdP's description stays in the log, not in the answer (it may name the app's ids).
- **Nothing stored**: a grant's minted token is not marked failed; the next read tries again, and works once the
  operator has fixed it. At the exchange (`mintAtGrant`), the same as an outage there: left to be minted lazily
  from the subject token while it lives (a grant that keeps none has nothing to mint from: a new session).
- **The refresh token is kept**: a refresh refused for the client did not spend it; the grant keeps it.
- **The log**: `Error` (not `Warn`): "the identity provider refused the service's own client", with the issuer
  and the IdP's code and description (no token, no secret; descriptions are already redacted of what was
  presented). The audit's outcome is `error`, as for an outage; the mint metric's outcome follows.
- **No protocol change**: `503 service_unavailable` is the protocol's answer for "try later: what the service
  depends on is unreachable for now" (protocol.md), and the minting section already names both answers.

## Enforcement & security

- Fail closed: the caller gets no material, as before; only the status and the detail change.
- A grant is not left refused by a fault that was not its user's.
- Many reads while it lasts each try the IdP once (as during an outage today); the IdP's own rate limits apply.

## Testing

- `internal/testidp`: the client refused with `invalid_client` and with `unauthorized_client`, switchable.
- The API: directly → 503 (was 403); under a grant, lazy mint and refresh → 503 and the grant's minted token not
  marked failed; the client fixed → the next read mints. An `invalid_grant` still ends the session (403, stored).
- The audit's outcome `error`; the answer's detail carries none of the IdP's description.

## Alternatives considered

- **`invalid_scope`, `invalid_target` too**: those name a secret's parameters (its audience, its scope) - an
  administrator's mistake in one secret, refused for that secret; they stay refusals (403).
- **Keeping 403 with a better detail**: a client retries 503 and not 403, and the grant's stored refusal is the
  real harm.
