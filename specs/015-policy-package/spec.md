# Spec 015: `internal/policy` - the permission model in a package of its own

- **Status**: implemented
- **Date**: 2026-10-08
- **Author**: hugr lab

## Summary

Spec 002's follow-up: the permission model (tresor specs/009 - admins manage, roles use, a delegation grant acts
with the server's own rights) moves out of `internal/api` into `internal/policy`. A pure refactor: no behaviour
changes, the protocol and the configuration are untouched.

## Problem

The rules lived as `Server` methods and helpers spread over `internal/api` (`isAdmin`, `verbs`, `mayCreate`,
`usable`, `roleOrGroup` in `api.go`; `actorVerbs`, `actorAllowed` in `delegation.go`), next to
HTTP handling. They could only be tested through HTTP requests, and the console's views (`admin.go`) reached
into the same helpers.

## Design

- `internal/policy`: `New(config.Policy) *Policy` with `IsAdmin`, `Verbs`, `MayCreate`, `ActorVerbs`,
  `ActorAllowed`; the functions `Usable`, `RoleOrGroup`; `ManageVerbs`. It depends on `auth`,
  `config` and `state` only - no HTTP, no store.
- `internal/api` holds a `*policy.Policy` and calls it; the code moved as it was (`mayCreate`'s unused name
  parameter dropped; `validPrincipal`, which nothing called, removed).

## Enforcement & security

Unchanged: every decision is the same function over the same inputs. The API's tests (every permission case
through HTTP) and the conformance suite run as before.

## Testing

- `internal/policy`: unit tests of the model - an admin's verbs, a role's `use`, a subject grant giving nothing,
  under a delegation grant the actor's `use` and an admin user's management only as the actor policy passes it,
  creation through a server, actors per issuer, principals.
- `internal/api`'s tests and the conformance suite, unchanged and passing.

## Alternatives considered

- Leaving it in `internal/api`: the follow-up was spec 002's, and the console grew a second user of the rules.
