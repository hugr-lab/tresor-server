# Spec 024: generated values in variables

- **Status**: accepted (the owner, 2026-10-18: "as for secrets"; tresor spec 037, hugr-lab/tresor#61)
- **Date**: 2026-10-18
- **Author**: hugr lab

## Summary

A variable's value is made on each read, as a secret's parameter is (spec 023): `mint+exchange://`,
`mint+claim://`, `mint+login://` / `mint+rule://`, whole or inside the string (`${…}`), for the effective user. tresor
spec 037 lets a variable's `GET` carry `expires_at` and requires such a value be `sensitive`; the client caches it
until shortly before then. A client puts it wherever DuckDB takes a string - a setting, a query.

## Design

- **The same syntax and kinds as a secret's** (spec 023), the same escapes (`mint++`, `$${`), checked at the write
  the same way; a reference (`ref+…`) is still never read as a generator.
- **The marker**: a variable with a generated value is `dynamic` (the row's marker, in place since spec 023's
  migration and CRD), and its descriptor is `sensitive` - in a list too.
- **The read**: the value made for the effective user (the caller; under a delegation grant the grant's user), its
  `expires_at` the earliest expiry less `dynamic.margin`, never `null` when generated; `sensitive: true`. A refusal
  is `403 mint_refused`, an outage `503` - never an empty value.
- **A login's field in a variable**: a variable has no scope, so a login (or rule) feeds one only when its scope (a
  rule's: and its identity's destinations) names it: `variable://<name>` - that name exactly - or `variable://`
  for every variable. A calling login's scope begins with the base URL it calls; its further entries are base URLs
  or `variable://` names, nothing else (a postgres:// there would let a login's fields reach a secret unbounded).
- A value longer than 64 KiB once made is refused (`403`).
- **A grant** keeps the claims, and pre-mints the exchanges, the variables its server may use name - as for secrets.
- No state migration, no protocol change of this service's own (tresor spec 037 is the protocol's).

## Enforcement & security

Only administrators write a variable (as now). A generated value is always `sensitive`: the client logs and shares
it as material. A variable written before 0.6 is not dynamic and makes nothing (as a secret, spec 023) - but its
escapes (`mint++`, `$${`) are read, as a secret's in 0.5; written again, a text that is not a valid generator is
refused.

## Testing

API tests: a claim and an exchange in a variable (whole and inside), `expires_at` and `sensitive`, the list's
`sensitive`, a login field only with `variable://<name>` in its scope, under a delegation grant the user's, a
static variable served as stored. tresor's conformance at its main.
