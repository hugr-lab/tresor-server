# Spec 006: token exchange without a client secret, and ZITADEL

- **Status**: accepted
- **Date**: 2026-10-01
- **Author**: hugr lab

## Summary

A `token_exchange` secret (tresor specs/010) makes the service mint a token for its caller at the caller's
identity provider, with RFC 8693 token exchange. The service logs in to the IdP as a confidential client.
Today that login is a client secret from the environment: the last static secret of the service's own on
Azure and Kubernetes.

The service gets four ways to log in without one:
- **a federated credential on Entra**: the service's managed or workload identity;
- **a Kubernetes ServiceAccount token**: Keycloak's federated client authentication, or any IdP that trusts
  the cluster's issuer;
- **`private_key_jwt` signed in Key Vault**: the private key never leaves the vault;
- **`private_key_jwt` with a key file**: the IdP's own key file, for a stack with no KMS.

**ZITADEL** becomes a supported IdP, as the issuer of callers and for token exchange.
- It is for **a stack with no Azure at all**: a sovereign European cloud, Hetzner say, Kubernetes with no
  cloud identity and no KMS.
- There, the service logs in with `private_key_jwt` and ZITADEL's key file, mounted from a Kubernetes
  Secret. The key is asymmetric: it never crosses the wire, and is revoked and replaced in ZITADEL.
- Signing in HashiCorp Vault or OpenBao (Transit) comes with phase 4, which brings Vault.

## Problem

- `exchange.client_secret_env` is a long-lived secret. It has to be rotated by hand, can leak, and works
  against the "no static secret where the platform has an identity" rule (CLAUDE.md).
- Entra, Keycloak and others accept a client assertion instead of a secret, each from their own source.
- ZITADEL issues roles as an object: the service reads a roles claim only as a list, so a ZITADEL caller
  has no roles.

## Design

### `exchange.client_auth`

```yaml
issuers:
  - issuer: https://login.microsoftonline.com/<tenant>/v2.0
    exchange:
      client_id: <the service's app registration>
      client_auth: azure            # secret (default) | azure | file | keyvault | key_file
```

| `client_auth` | The client assertion (`client_assertion_type` jwt-bearer) | For |
| --- | --- | --- |
| `secret` | none: `client_secret_env`, as today | any IdP |
| `azure` | a token of the service's Azure identity (`azure.identity`: managed or workload), for the audience `api://AzureADTokenExchange` | Entra: the app registration has a federated credential of the kind Managed identity, naming that identity (on AKS too) |
| `file` | `assertion_file`: a file read at each request, such as a projected ServiceAccount token with an `audience` of the IdP's choosing | Keycloak (federated client authentication), any IdP trusting the cluster's issuer |
| `keyvault` | a JWT the service makes (`iss` = `sub` = the client id, `aud` = the issuer, `jti`, a few minutes) and has signed in Key Vault: `key` (a Key Vault key URL), `kid` (what the IdP knows the key by) | Keycloak, Entra (`kid` the certificate's `x5t`), ZITADEL (its key imported), any IdP with `private_key_jwt`, on Azure |
| `key_file` | the same JWT, signed with a private key from `key_file`: a ZITADEL key file (JSON: `keyId`, `key`, `clientId`) or a PEM key with `kid`. Read again when it changes | ZITADEL; any IdP with `private_key_jwt`, on a stack with no KMS |

- **One per issuer.** `client_secret_env` is refused with any `client_auth` but `secret`.
- **An assertion per request**, never cached: an IdP may refuse a `jti` it saw (Keycloak), and a lifetime of
  one minute is enough. A projected token file is read at each request, since the kubelet rotates it. A
  `key_file` is read at start: a rotation restarts the pods.
- **The KEK's rights are not reused.** `keyvault` signs with a key of its own, under its own role: sign
  only, on that one key.
- **`key_file` is a static key** of the service's own, the one kind left. It is asymmetric, never sent, and
  revocable at the IdP. The chart mounts it from a Secret; the docs say to rotate it in the IdP.
- **The chart** mounts the projected token for `file`: `exchangeToken.audience`, at
  `/var/run/tresor/idp-token/token`.
- **The JWT's header** names the key by `kid`, and by `x5t` when it is set (Entra's certificates, which are
  RSA). For Entra, `assertion_audience: token_endpoint`.
- **Readiness**: an issuer with an exchange client checks that it can make its assertion (the file reads,
  the identity gives a token, the key signs). It does not log in at the IdP.

### ZITADEL

- **As an issuer of callers.**
  - The issuer is the instance's domain (`https://<instance>.zitadel.cloud`); the JWKS is found by
    discovery.
  - The access token must be a **JWT**: in the ZITADEL app, set the access token type to JWT and enable
    "User roles inside Access Token". The default is opaque, and the service verifies JWTs only.
  - **Roles as an object.** `roles_claim: urn:zitadel:iam:org:project:roles` reads the object's keys as the
    roles. This holds for every IdP: a roles claim that is an object gives its keys, one that is a list
    gives its items.
- **For token exchange** (ZITADEL 4.11 or later, where it is GA):
  - The service's client is an OIDC app with the grant type "Token Exchange".
  - **The audience can only be narrowed.** A downstream project must already be in the caller's token. The
    caller's login asks for it with the scope `urn:zitadel:iam:org:project:id:<project>:aud`, which tresor
    sends from the issuer's `scopes` in the discovery.
  - **No refresh token by exchange.** The service asks for an access token only, and exchanges again when
    it expires, as long as the delegation grant's subject token lives. Today Keycloak gets a refresh token
    and ZITADEL is refused ("TypeNotSupported"). That refusal is read as "unsupported", not as a failure.
  - **Client authentication**: `secret`, or `private_key_jwt` with ZITADEL's key.
    - ZITADEL generates the key pair: an app key cannot be registered from a public key.
    - **`key_file`** (the expected set-up, with no Azure): the downloaded JSON key file in a Kubernetes
      Secret, mounted for the service.
    - **`keyvault`**, where there is Azure after all: the key is imported into Key Vault and the file
      destroyed; the vault signs from then on.
    - Workload identity federation does not exist in ZITADEL (issue 7173): `azure` and `file` do not apply
      to it.

### What changes

- `internal/mint`: the client's authentication becomes an interface: a secret, or an assertion from a
  source.
- `internal/clientauth`: the sources - a token for `api://AzureADTokenExchange` from the configured identity
  (the public cloud's audience), a file, a signed JWT.
- `internal/keys/azurekeyvault`: signing a JWT with a named key (RS256; ES256 for an EC key).
- A local signer for `key_file`: a ZITADEL key file or a PEM key.
- `internal/auth`: a roles claim that is an object.
- `internal/config`: `client_auth`, `assertion_file`, `key`, `kid`, validated per kind.
- The chart: the projected token.
- The docs: Entra, Keycloak and ZITADEL set-ups. No protocol change.

## The PRs

1. **(a) client authentication** (landed):
   - `client_auth` with `azure`, `file`, `keyvault` and `key_file`;
   - a roles claim that is an object;
   - the chart's projected token;
   - the docs (a Token exchange page);
   - ZITADEL's refusal of a refresh (`TypeNotSupported`) read as unsupported: a grant gets an access
     token only, and exchanges again (from its documented wording, checked live in b);
   - `x5t` in the header, for Entra's certificates.
2. **(b) ZITADEL in CI, and the stack with no Azure on kind**:
   - ZITADEL in docker, an exchange through `key_file`;
   - the recipe: ZITADEL, the Kubernetes store, a local KEK.

## Enforcement & security

- **Fail closed.** If no assertion can be made, the mint fails (`503`). There is no fallback to a secret
  and no unauthenticated request.
- **No assertion and no token is logged or put in an error.** IdP errors keep their code and description,
  as today.
- **Least privilege.**
  - `azure`: the identity is federated with the one app registration.
  - `file`: a projected token with its own audience, never the ServiceAccount's API token.
  - `keyvault`: sign on one key.
- **The assertion's audience is the IdP's** (its issuer, or its token endpoint where the IdP requires
  that), so it is never accepted elsewhere. Lifetimes are minutes, and each JWT has a fresh `jti`.

## Testing

- **Each source**, against a fake token endpoint that checks the form:
  - `client_assertion_type`, and an assertion's claims and signature;
  - a rotated file read again;
  - an identity that gives no token: refused, with no secret sent.
- **ZITADEL**, in the CI (docker: ZITADEL and its database):
  - an OIDC app with token exchange;
  - a person's JWT with roles as an object;
  - `whoami` with those roles;
  - a `token_exchange` secret minted for them, through `key_file` (ZITADEL's own key file);
  - the refresh refusal handled.
- **Live, by hand**: Entra with the service's managed identity as the federated credential (Container
  Apps), and Keycloak's federated client authentication on kind.
- **The Hetzner-like stack**, on kind and documented as a recipe:
  - ZITADEL as the IdP, the Kubernetes store, a local KEK from a Secret, `key_file`;
  - nothing of Azure, nothing of a cloud identity.

## Open questions

- Keycloak's federated client authentication for Kubernetes tokens: the Keycloak version where it is
  supported (not a preview), and its realm set-up, are checked before (b) is built.
- Whether Entra accepts a managed identity as a federated credential in every cloud (sovereign clouds).

## Alternatives considered

- **The service's identity token as the subject's actor** (RFC 8693 `actor_token`). That is delegation at
  the IdP, which ZITADEL calls impersonation. It does not replace the client's authentication.
- **A client secret from Key Vault** (`ref+azkv`). It is still a static secret, only kept better: rotation
  and leaks remain.
- **A ZITADEL machine user with its own public key** (the jwt-bearer grant). It authenticates a user, not
  the OIDC client token exchange needs.
