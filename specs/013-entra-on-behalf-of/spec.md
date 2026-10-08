# Spec 013: Entra On-Behalf-Of for `token_exchange` secrets

- **Status**: draft
- **Date**: 2026-10-08
- **Author**: hugr lab

## Summary

A `token_exchange` secret (tresor specs/010) is minted today with RFC 8693's token-exchange grant: Keycloak and
ZITADEL accept it, Entra ID does not. Entra's equivalent is On-Behalf-Of (OBO): the caller's token as a JWT bearer
assertion, a scope for the downstream API. This adds OBO as an issuer's exchange grant, so a service on Azure mints
tokens for its callers through Entra - with no client secret, its managed identity as the app registration's
federated credential (`client_auth: azure`, spec 006). tresor's client side has OBO already (its specs 008, 013,
015); the server's mint did not.

## Problem

`website/docs/token-exchange.md` describes Entra with a federated credential, but the mint sends
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, which Entra refuses (`unsupported_grant_type`). An
installation on Azure cannot use `token_exchange` secrets with Entra as its IdP at all. Spec 006's open question on
Entra's managed identity as a federated credential cannot be checked live until this works.

## Design

### Configuration

```yaml
issuers:
  - issuer: https://login.microsoftonline.com/<tenant>/v2.0
    audience: <the service's app id URI or client id>
    exchange:
      client_id: <the service's app registration's client id>
      client_auth: azure            # the managed identity, a federated credential on the app registration
      grant: on_behalf_of           # token_exchange (default; RFC 8693) | on_behalf_of (Entra)
```

- `exchange.grant` is the server's own setting: the protocol is unchanged. A secret's params stay `audience` and,
  optionally, `scope` (tresor specs/010).
- `on_behalf_of` with `client_auth: secret` is accepted too (a client secret, for a tenant that has nothing
  else), as Entra accepts it; the docs lead with `azure`.

### The request (OBO)

```
grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
assertion=<the caller's access token>
requested_token_use=on_behalf_of
scope=<the secret's scope, or <audience>/.default>
+ the client's authentication (client_assertion, or client_secret)
```

- **The scope**: Entra asks for scopes, not an audience. The secret's `scope` param is sent as it is; without one,
  `<audience>/.default` (the downstream API's app ID URI or client id, all its delegated permissions consented).
- **A refresh token**: with the secret's refresh (as for RFC 8693), `offline_access` is added to the scope; Entra
  answers with a refresh token, renewed by the refresh grant as today.
- **The caller's token** must be for this service (its `aud` the service's app): the same token the service
  verified; Entra checks it again.
- **Errors**: Entra's codes map as the others' (`invalid_grant` - the caller's session or consent; `invalid_client`
  - the service's credential), and its description never carries a token. An `AADSTS` code is kept in the
  description, for whoever reads the log; nothing else of Entra's message is.

### The subject

OBO keeps the caller as the token's subject (`oid`, `upn`): the minted token is for the person, on behalf of whom
the service acts - what a `token_exchange` secret means. A caller with no user (a client-credentials token, an app)
gets Entra's refusal, mapped as `invalid_grant`: OBO is for users.

## Enforcement & security

- **No static secret**: with `client_auth: azure` the service authenticates by its managed identity's token for
  `api://AzureADTokenExchange`, the app registration's federated credential; nothing is stored.
- **Fail closed**: an OBO refusal is the mint's refusal (`403 mint_refused`, as today), never a token of another
  scope or for another subject.
- **Scope**: the minted token carries what was consented for the downstream API; the secret's `scope` cannot widen
  it beyond the consent, which the tenant's administrator grants.
- **Logs and audit**: the scope and the downstream audience are logged, never a token.

## Testing

- Go: the mint's OBO request (the form, the scope rules, `offline_access` with a refresh), Entra's errors mapped,
  against the in-process issuer (`internal/testidp`) answering OBO; config validation (`grant`, combinations).
- Live, by hand, on Azure with the owner's agreement on resources, deleted the same day:
  - a Container App with a user-assigned managed identity running the service;
  - two app registrations: the service (a federated credential naming the managed identity; an exposed API scope)
    and a downstream API; admin consent for the service to call it on behalf of users;
  - a test user's token for the service; a `token_exchange` secret read: a token minted by OBO, for the user, for
    the downstream API - the service holding no secret.
  This also settles spec 006's open question on the managed identity as a federated credential.

## Alternatives considered

- **Choosing the grant per secret** (a param): the grant follows the IdP, which is the issuer's; a param would let a
  writer pick a grant the IdP does not have. Rejected.
- **Detecting Entra from the issuer URL**: a guess; a sovereign cloud's or a B2C issuer would be missed. An explicit
  setting. Rejected.
- **A protocol change** (an `on_behalf_of` provider): the secret means the same thing - a token for the caller -
  whatever the IdP calls the grant. Rejected; tresor's protocol is untouched.

## Follow-ups

- Sovereign clouds: the federated credential's audience (`api://AzureADTokenExchangeUSGov`, …) as a setting.
