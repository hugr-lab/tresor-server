# Spec 004: variables

- **Status**: accepted
- **Date**: 2026-10-01
- **Author**: hugr lab

## Summary

tresor spec 018 adds **variables** to the protocol, as an optional part: named strings a service holds for its
callers. tresor-server supports them on every state store. The protocol is tresor's (`website/docs/protocol.md`,
"Variables"); this spec covers how the service keeps and serves them.

## Decisions (2026-10-01, the owner)

- After the Helm chart (spec 003, d), before the docs and the AKS run (003, e).
- **A value is always sealed at rest**, as a secret's params are. A plain value may still be a connection
  string with a password, and the protocol's `sensitive` covers only resolved references.

## Design

### The state: a second namespace

`state.Store.Variables()` is the variables' store, with the same interface as the secrets' store: `List`,
`Describe`, `Get`, and `Update` (compare-and-set on the version).
- A variable is a `state.Secret` of type `variable`, whose params hold `value`.
- The grants, versions, owner and times are the secrets'.
- Delegation grants are one store's: `Variables().Delegations()` is the secrets' store's.
- **Sealed** under the envelope with an AAD of its own (`tresor-server/variable/1\x00row\x00name\x00version`),
  so a sealed variable never opens as a secret, nor a secret as a variable.

| Store | Where |
| --- | --- |
| memory | a second map |
| SQLite, PostgreSQL, SQL Server | tables `variables` and `variable_grants`, the secrets' columns (migration 0005) |
| Kubernetes | `TresorVariable` (`v-<hash>`), the `TresorSecret`'s spec, its MAC under kind `TresorVariable` |

On Kubernetes the new CRD comes with the chart's `crds/`, which Helm does not upgrade. An install from before
runs `kubectl apply --server-side -f crds/` first, or the service does not start (its schema check).

### The API

- The routes are the protocol's. `capabilities.variables: true` is set in the discovery.
- The secrets' handlers serve both namespaces. The namespace comes from the **matched route** (`r.Pattern`),
  never from the decoded path: a secret named `a/v1/variables` stays a secret.
- **The value** is a UTF-8 string of at most 64 KiB (`422` beyond). A read of the value sends
  `Cache-Control: no-store` and the ETag.
- **References.** A value that starts with `ref+` is a reference, under the secrets' rules:
  - written by an administrator only, to a configured source within its allowlist;
  - resolved at each read.

  A reference that does not resolve fails the read:
  - `503 service_unavailable` when it may resolve later (the source does not answer, or the secret is
    missing);
  - `500 service_error` when it will not (it is outside the allowlist now).
- **`sensitive`** is `true` when the value is a reference: the resolved value is material. It is marked in
  the variable's `provider` (`reference`), so a list knows without opening the value, and a read that
  resolved one says `true` whatever the marker. A plain value is `false`, though it is sealed at rest all
  the same.
- **A value that looks like a reference is one.** `ref+…` (any case, after spaces) must be a valid reference
  within the allowlist (`422` otherwise), as for a secret's params. The protocol's 64 KiB of any string
  yields to that: such a text cannot be kept as a plain value.
- A source that answers but holds nothing usable (missing, disabled) is `503`: the vault's owner may fix it
  at any time. A stored value that does not read is `500`.

### Conformance

- tresor's pin moves to spec 018 or later.
- `scripts/ci/conformance.sh` exports `TRESOR_CONFORMANCE_VARIABLES=1`, so tresor's `variables.test` runs on
  every store.

## Testing

- The state suite runs on the variables' namespace too: the same cases, on every store.
- The two namespaces are kept apart:
  - a name in both is two entries;
  - a sealed value moved between them does not open;
  - on Kubernetes, a variable's resource made into a secret's does not verify.
- The API:
  - each route, the 404/403 rules, conditional writes, the 64 KiB limit;
  - a reference resolved, its failures (503 and 500), and `sensitive`;
  - a secret named like a variables path.
- tresor's conformance suite, variables included, on every store.

## Alternatives considered

- **A `namespace` column in the secrets' tables.** It would change their primary key, migrating every
  existing database's largest tables. Two tables of the same shape take one migration that adds, and keep
  the same queries.
- **Plain values at rest.** Refused by the owner: a value is anyone's string, and may well be material.
