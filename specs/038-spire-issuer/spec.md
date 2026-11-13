# Spec 038: SPIFFE workloads - SPIRE as an issuer, roles by the SPIFFE ID

- **Status**: implemented (#111; the owner, 2026-11-12: "давай пойдём таким путем" - SPIFFE, path B, a live check with a
  Cloudflare tunnel)
- **Date**: 2026-11-12
- **Author**: hugr lab

## Summary

A workload with a SPIFFE identity (a JWT-SVID from SPIRE) reaches the service with no secret: through Keycloak
(tresor specs/046, `jwt-spiffe`), through Entra's workload identity federation (`jwt-bearer`), or with the SVID itself
as its bearer token, the service trusting SPIRE's OIDC discovery as an issuer ("path B"). The last needs roles, which an
SVID does not carry: the issuer's `role_rules` give them by the SPIFFE ID. Research: `design/spiffe-roles.md` (local) -
the same model in duckdb-acl (`CLIENT … REQUIRE sub LIKE … ROLES CONSTANT`) and kista (client grants).

## Design

- **`issuers[].role_rules`**: `[{subject, roles}]` - a token whose `sub` matches `subject` (`path.Match`, `*` within one
  segment) holds `role:<r>` for each role. Checked at load (a pattern, roles named as a roles claim has them, no
  prefix); applied after the roles claim, without duplicates; any issuer, but meant for SPIRE. Config only: roles are
  the operator's, never a caller's.
- **A revoked key stops verifying within a readiness check** (review finding, every issuer): go-oidc's key cache
  reads an issuer's keys again only for a kid it does not know, so a key the issuer stopped publishing (SPIRE's after
  `localauthority … revoke`, any IdP's) verified until a restart while new tokens named known kids. The readiness check
  already fetches each issuer's keys every 30 s; when their digest changes the verifier is dropped and made again at
  the next token, with the current keys.
- **SPIRE as an issuer** needs nothing new: its discovery and keys are an OIDC issuer's; `service: {claim: sub,
  client_claim: sub}` makes every SVID a service's, `client:spiffe://…`.
- **Docs**: a SPIFFE page (the three ways; SPIRE settings: `jwt_issuer`, RS256 for Entra, `set_key_use`; the issuer;
  rotation and revocation); `role_rules` in Configuration.
- **Live script** `scripts/dev/spire_live.sh` (+ `scripts/dev/spire/`): SPIRE whose SVIDs carry `iss` (a Cloudflare
  quick tunnel's https URL to its discovery) and are RS256; a local service trusting it; Entra's federated credential
  on the node app (temporary, removed by `entra-down`).
- The DuckDB side of path B - the SVID read from a file as the token - is tresor's (its specs/047, `TOKEN_FILE`).
- No protocol change.

## Testing

- Go: a key the issuer no longer publishes - still verifying from the cache before a check, refused after it, the new
  key accepted (the test IdP's `Rotate`).
- Go: `role_rules` - a segment glob, two rules, no duplicate, no match deeper or in another trust domain; config
  refusals (a bad pattern, no roles, a prefixed role).
- **Live, 2026-11-12** (SPIRE 1.13.0, a quick tunnel, the owner's Entra tenant, Keycloak 26.8.1):
  - SPIRE as an issuer: discovery behind the tunnel (RSA, RS256, use sig); readiness ok; the node's SVID →
    `role:nodes`, `client:spiffe://…`; an admin SVID (`role_rules` → `secrets_admin`) creates a secret and grants
    `role:nodes`; the node reads it (200); an attested workload no rule names reads nothing (404); an SVID for
    another audience 401;
  - Entra: a federated credential (issuer = the tunnel, subject = the SPIFFE ID, `api://AzureADTokenExchange`) - the
    node's SVID exchanged by `jwt-bearer` for an Entra token with the app role `nodes`; the service took it
    (`role:nodes`, `client:<app>`); the credential removed afterwards;
  - Keycloak 26.8.1's SPIFFE authentication took an SVID **with** `iss` (`jwt-spiffe`, token issued): one SPIRE with
    `jwt_issuer` serves all three ways.

## Follow-ups

- The service's own exchange client by an SVID (`exchange.client_auth: file` with a `jwt-spiffe` assertion type).
- duckdb-acl and kista: the same subject-pattern rules, one format (design note).
