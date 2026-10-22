# Spec 030: whoami names the person; an IdP's own roles left out

- **Status**: accepted (the owner, 2026-10-22: "wait for tresor, then do it"; tresor spec 041)
- **Date**: 2026-10-22
- **Author**: hugr lab

## Summary

On a demo run `whoami` showed a person as the IdP's opaque `sub`, and Keycloak's own roles (`offline_access`,
`uma_authorization`, `default-roles-*`) among the roles. tresor spec 041 adds an optional `name` to `whoami` (for
people to read, never an identity); this service gives it, and lets an issuer leave an IdP's own roles out.

## Design

- **`name`**: the first non-blank, trimmed of `preferred_username`, `name`, `email`, `upn` - no control character,
  256 characters at most; absent when there is none. Kept with a delegation grant (the grant keeps only the
  claims its secrets name - spec 023 - so the name is a field of its own): under a grant, the user's. Nothing is
  granted, owned or audited by it: identity and ownership stay `subject`.
- **`ignore_roles`** (per issuer): glob patterns (`path.Match`) of the roles claim's values never taken as
  principals; checked at load.
- The console shows the name from its own sign-in, else whoami's, else the subject.
- tresor pinned at 594fcca (v0.1.0, specs 040 - device-flow PKCE - and 041).

## Testing

API: the name from each claim in turn, absent without one, under a grant the user's; ignore_roles leaving
Keycloak's roles out. Config: a bad pattern refused. tresor's conformance at the pin.
