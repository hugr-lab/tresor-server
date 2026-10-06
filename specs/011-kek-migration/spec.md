# Spec 011: moving to another KEK - `keys.previous`, then `rewrap`

- **Status**: draft
- **Date**: 2026-10-06
- **Author**: hugr lab

## Summary

An installation can move its data keys from one KEK to another: from a local key to Key Vault, from Key Vault
to OpenBao's Transit, from one vault's key to another's. The new KEK becomes `keys`, the old one is listed under
`keys.previous` (read only: it unwraps, it never wraps), `tresor-server rewrap` wraps every data key under the
new one, and `keys.previous` is removed. The values are not touched. Spec 002's follow-up.

## Problem

`rewrap` (spec 002) moves data keys between the versions of **one** KEK. Every wrapper refuses a KEK id that is
not its own (`ErrSealed`), so with a new `keys` the stored data keys no longer open: a move today means exporting
every secret through DuckDB and writing it again, by hand, with its grants. A development install that started on
a local key cannot become a production one under Key Vault or Vault.

## Design

### Configuration

```yaml
keys:
  kind: azurekeyvault
  key: https://corp-kv.vault.azure.net/keys/tresor-kek
  previous:                          # read only: data keys still under these open; nothing new is wrapped
    - {kind: local, key_file: /var/run/tresor/kek-old/kek}
```

- `keys.previous[]` takes a KEK's own settings (`kind`, `key_env`, `key_file`, `key`, `mount`); not
  `data_key_max_age` or `cache_ttl`, which are the store's.
- A previous KEK that is the current one (the same key) is refused at start: it would hide a typo.
- From the environment: `TRESOR_KEYS__PREVIOUS` as a YAML list (spec 002's rule for lists).

### The wrappers

- Each KEK says which KEK ids are its own: `Owns(kekID) bool` (local: its id; vault: `vault:<mount>/<key>:v*`;
  Key Vault: its key's URL, any version). Two configured KEKs owning one id is refused at start.
- A chain wraps them: `Wrap` and `Current` are the current KEK's; `Unwrap` and `Root` go to the KEK that owns
  the id. An id no configured KEK owns is `ErrSealed`, as today.
- Nothing else changes: a data key's tag is checked under its own KEK's root (spec 003), so a data key planted
  under a previous KEK still has to be authentic.

### The service

- Values under a previous KEK's data keys read as before.
- The first write after the change seals under a new data key wrapped by the new KEK: the active data key is
  replaced when its KEK id is not the current one (spec 002, unchanged).
- Readiness checks each previous KEK too (it gives its current id or its root): a previous KEK that does not
  answer makes the service not ready, since the values under it would not open.
- `/admin/v1/service` and the console's Service screen list the previous KEKs (kind and id, never key material).

### The move

1. Configure the new KEK as `keys`, the old one under `keys.previous`; deploy. (Until step 2 this can be undone
   by swapping them back: nothing has been wrapped under the new KEK but new data keys, which the swap back
   would then need as previous.)
2. `tresor-server rewrap`: every data key wrapped under the current KEK, tags made under its root. It says how
   many it moved and names any it could not (as today); run again until it moves none.
3. Remove `keys.previous`; deploy. A data key still under the old KEK is now `ErrSealed` at its first read:
   fail closed, never an empty value. The old KEK can then be retired.

`rewrap` with no `keys.previous` behaves as today.

### The chart

`localKEK.previousSecretName`: a previous local KEK from a Secret, mounted at `/var/run/tresor/kek-previous/`,
and listed in `config.keys.previous` when that is unset. Other kinds need nothing mounted.

## Enforcement & security

- **Read only.** A previous KEK never wraps; `Current` is always the new one.
- **Fail closed.** An id no KEK owns, a data key whose tag does not match, a previous KEK that does not answer:
  errors, never an empty value. After step 3 nothing under the old KEK opens.
- **No downgrade.** A data key's tag binds its KEK id; moving it under the old KEK again needs the old KEK's
  root, which only its holder computes.
- **The old KEK's material** (a local key file) is needed only until step 3; the docs say to remove it then.
- **Logs** name KEK ids and data key ids, never key material, as today.

## Testing

- Go: the chain (wraps with the current, unwraps by owner, an unowned id refused, two owners refused); the
  envelope across a move - values sealed under A, then current B with A previous: values read, a new write
  under a B data key, `rewrap` moves every data key, then B alone reads everything; a data key still under A
  with A removed: `ErrSealed`.
- Config: `keys.previous` parsed and validated (a missing key, the current KEK repeated); from the environment.
- The command: `rewrap` local → local (two files) against SQLite, end to end.
- CI: local → OpenBao Transit on kind (spec 007's `kind.sh`), the conformance suite passing before and after
  `rewrap`.

## Alternatives considered

- **`rewrap -from <config>`**, the old KEK only in the command. The service could not read the values between the
  new KEK's deploy and the rewrap; the move would need downtime. Rejected.
- **Re-sealing the values** under new data keys. Every value rewritten for what only needs the data keys
  (a handful) rewrapped. Rejected.
- **Unwrapping by trying each KEK.** An `ErrSealed` from the wrong KEK and a tampered data key look alike;
  routing by owner keeps them apart. Rejected.

## Follow-ups

- Phase 4's KEKs (AWS KMS, GCP KMS) own their ids the same way.
