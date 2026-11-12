---
title: SPIFFE workloads
---

# SPIFFE workloads

A workload with a [SPIFFE](https://spiffe.io) identity - a JWT-SVID from SPIRE - reaches the service with no secret
of its own: the SVID proves who it is, short-lived and renewed by SPIRE. Three ways, all checked live (spec 038):

| Way | The workload sends | Roles come from | When |
| --- | --- | --- | --- |
| **Keycloak** | the SVID to Keycloak (`jwt-spiffe`), its token to the service | the Keycloak client's service account | Keycloak 26.4+ (SPIFFE support is a preview feature) |
| **Microsoft Entra ID** | the SVID to Entra (workload identity federation, `jwt-bearer`), its token to the service | the app's app roles | Azure |
| **SPIRE as an issuer** | the SVID itself, as the bearer token | this service's `role_rules`, by the SPIFFE ID | no IdP in between: AWS, GCP, on premises |

In the first two the service sees an ordinary token of its identity provider - nothing to configure here. The node's
side is tresor's: `FLOW 'federated'` with the SVID as its assertion (tresor specs/046), or the SVID as the token
(tresor specs/047).

## SPIRE

One SPIRE serves all three: its JWT-SVIDs carry `iss` - the public https URL of its OIDC discovery provider - and
Keycloak, Entra and this service all take them.

```hcl
server {
    trust_domain        = "corp.example"
    jwt_issuer          = "https://spire-oidc.corp.example"   # the discovery provider's public URL
    ca_key_type         = "rsa-2048"                           # Entra takes RS256 only, not SPIRE's default ES256
    jwt_key_type        = "rsa-2048"
    default_jwt_svid_ttl = "5m"
}
```

The OIDC discovery provider (`oidc-discovery-provider`) serves `/.well-known/openid-configuration` and `/keys` at that
URL, with `set_key_use = true` (Entra wants `use: sig`). It publishes only public keys; it must be reachable by https
from whoever verifies the SVIDs - Entra and Keycloak from the internet or your network, this service from its own.

## SPIRE as an issuer

```yaml
issuers:
  - issuer: https://spire-oidc.corp.example
    audience: duckdb-secrets                      # the SVID's aud: the workload asks SPIRE for it
    service: {claim: sub, client_claim: sub}      # every SVID is a service's: client:spiffe://…
    role_rules:
      - {subject: 'spiffe://corp.example/hugr/node/*', roles: [nodes]}
      - {subject: 'spiffe://corp.example/platform/admin', roles: [secrets_admin]}
policy:
  admins: [role:secrets_admin]
```

- **Identity** is the SPIFFE ID: `subject:<issuer>|spiffe://…`; the client principal is `client:spiffe://…` (for
  [actors](configuration.md), `policy.actors`).
- **Roles** come only from `role_rules` - the operator's, never the workload's. `*` stays within one path segment:
  `…/hugr/node/*` matches `…/hugr/node/group-a`, not `…/hugr/node/a/b` nor another trust domain. A workload SPIRE
  attests but no rule names holds no role, and sees nothing.
- **Grants** go to those roles, as for people ([Grants](https://hugr-lab.com/docs/tresor/protocol/)).
- **Roles in the SVID instead**: a SPIRE CredentialComposer plugin can put a `roles` claim into the SVIDs; then
  `roles_claim: roles` and no rules. The registration of a workload in SPIRE then decides its roles.

## Rotation and revocation

- **By time**: an SVID lives minutes (`default_jwt_svid_ttl`); SPIRE renews it before it expires, the workload reads
  the new one. SPIRE's signing keys rotate with an overlap in the published keys, which this service reads again.
- **A workload compromised**: delete its registration entry in SPIRE - no new SVID; an SVID already issued lives until
  its `exp`. Revoke what the service holds for it at once: its delegation grants
  (`DELETE /v1/delegations?actor=client:spiffe://…`), its rule in `role_rules`.
- **A node compromised**: evict or ban its SPIRE agent - no SVID for any workload on it.
- **SPIRE's key compromised**: rotate and revoke the key in SPIRE; once it leaves the published keys, tokens it signed
  are refused.

An SVID is a bearer token for its audience: keep its file to the workload, and its audience to one service.
