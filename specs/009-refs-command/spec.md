# Spec 009: `tresor-server refs` - the references that would not resolve

- **Status**: implemented
- **Date**: 2026-10-05
- **Author**: hugr lab

## Summary

A command that lists the stored references (`ref+…`, in secrets and variables) that the configuration given does
not admit: a source no longer configured (renamed or removed, spec 008), a place outside its allowlist now, a
reference that does not parse. With `-resolve`, it also reads each one, and lists those that do not resolve
(a deleted secret, a denied read). Spec 008's follow-up.

## Problem

- References are checked at a write, and again at each fetch. A configuration change (a source renamed or
  removed, an allowlist narrowed) strands references silently: they fail at their next fetch, in production.
- An administrator has no way to see them beforehand, short of reading every secret.

## Design

```sh
tresor-server refs -config server.yaml [-resolve]
```

- **What it reads**: every secret and variable in the configured store, opened with the KEK (`Get`); the
  configuration's sources (`material:`), built as the service builds them.
- **What it checks**: every string parameter that starts with `ref+` (a typed `{type, value}` too), against
  the sources: the parse and the allowlist, as at a fetch. `-resolve` reads it too, with the service's
  identity; the value is never printed nor kept.
- **What it prints**, one line per finding, tab-separated, on stdout:

  ```
  secret    lake      secret   invalid reference: no source for vault-us references is configured (material:)
  variable  region    value    invalid reference: ref+vault://secret/x#f is outside the allowlist (material.vault.allow)
  secret    old       -        does not open: sealed
  ```

  - the kind (`secret`, `variable`), the name, the parameter, the reason;
  - the reason is the source's error, as at a fetch: it names a reference only once it parsed, never a
    text that does not (spec 002: a text that is not a reference may be a value written by mistake);
  - a secret that does not open (sealed) is a finding, not a stop.
- **Exit**: `0` when there is nothing to report, `3` when there is a finding, `1` on an error (the store or
  the KEK unreachable).
- **A configuration to come**: run it with the new configuration against the live store before deploying it
  (the store's and the KEK's settings the same).
- **Read-only**: it writes nothing; opening a SQL store runs its migrations, as `rewrap` does.
- `memory` keeps nothing: nothing to check.

## Enforcement & security

- No value is printed or logged: the references' places and the sources' errors only.
- It needs the service's own rights (the store, the KEK; with `-resolve`, the sources'): it runs as the
  service, e.g. `kubectl exec` into a pod, or a job with the same identity.
- The output names secrets and parameters: it is for the service's operators.

## Testing

- Go: secrets and variables with references admitted, to a missing source, outside an allowlist, a typed
  value, a sealed secret; `-resolve` against a fake source; the exit codes.

## Alternatives considered

- **At start, a warning**: the service would open every secret at each start. Rejected: a start opens no
  material.
- **An admin route**: it would read every secret's params over the API. Rejected for now; the management UI
  (to come) may show it.
