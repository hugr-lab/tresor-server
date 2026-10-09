# Spec 018: `tresor-server reseal` - every row moved to the active data key, old data keys retired

- **Status**: accepted
- **Date**: 2026-10-09
- **Author**: hugr lab

## Summary

A data key is rotated by age (`keys.data_key_max_age`, 30 days), but only new writes use the new one: a secret
written once a year ago is still sealed, and MACed, under the data key of that day, and every data key ever made
stays stored. A data key that leaked (a memory dump, a debugger) keeps opening and forging the rows under it
until each is written again (specs 003 and 014 name this as a follow-up). `tresor-server reseal` moves every row's
sealed material and MAC to the active data key - a fresh one with `-rotate` - without changing a row's version,
and `-retire` then deletes the data keys no row uses any more.

## Problem

- **Rotation protects new rows only.** Rows are re-sealed when written; a quiet secret never is.
- **Data keys pile up.** One per 30 days per KEK, never deleted (`data_keys.retired_at` exists, unused).
- **A leaked data key**: the operator rotates the KEK (`rewrap`, spec 011) - that rewraps the data keys and keeps
  them, the leaked one included. Nothing moves the rows off it.

## Design

### The command

```sh
tresor-server reseal -config server.yaml            # every row onto the active data key
tresor-server reseal -config server.yaml -rotate    # a new active data key first (a leaked one)
tresor-server reseal -config server.yaml -retire    # then delete the data keys nothing uses
```

Like `rewrap` and `mac`: run while the service runs (every change is compare-and-set), on SQLite with the service
stopped. It logs counts and the ids of data keys, never a value; a row it cannot move is named and skipped, and
the command fails (exit 1) - run it again.

### What moves

For each store (SQL: SQLite, PostgreSQL, SQL Server; Kubernetes; `memory` has nothing at rest and is refused):

| Row | Moved |
| --- | --- |
| a secret, a variable | its material opened under its data key, sealed under the active one with the **same AAD** (its version unchanged), its MAC recomputed |
| a delegation grant | its subject token, the same; one with nothing sealed: its MAC under the active key |
| a minted token | its sealed tokens, the same (its version unchanged); one that failed: its MAC under the active key |
| Kubernetes: an actor's counter, the installation keyring | their MAC under the active key |

- **Not a write**: the version, the times and the ETag stay - a client's `If-Match` still holds, nothing is
  audited as an edit, and a replica reading meanwhile reads either form. Each move is compare-and-set on the row
  as read: SQL on its version and its old data key (and the old MAC), Kubernetes on the resourceVersion; a row
  written meanwhile is already under the active key and is skipped.
- **The MAC is checked first**: a row is moved only if its MAC verifies under its old data key - `reseal` never
  vouches for a row changed behind the store. One that does not verify, or (SQL) has no MAC yet (`tresor-server
  mac` first, spec 014), is named and skipped.
- **Under any KEK of the chain**: a data key wrapped by `keys.previous` (spec 011) opens; the active one is under
  the current KEK.
- `-rotate`: activates a new data key first, as rotation by age does, so the rows leave the active one too.

### Retiring

`-retire`, after the moves, deletes each data key that is:

1. not the active one;
2. **superseded long enough**: the next data key was made more than `keys.cache_ttl` (5 minutes) plus a minute ago
   - a replica may hold a superseded key as active for that long, and seal under it;
3. **used by nothing**: a scan of every row after the moves names none under it.

The scan and the delete are not one transaction, but nothing can start using a key that is neither active nor
cached (1, 2). SQL: `DELETE FROM data_keys WHERE id = ?` (the column `retired_at` is dropped from the plan: a
deleted key cannot open, a marked one still could); Kubernetes: the `TresorDataKey` deleted at its
resourceVersion. A key that is still used is kept and named; `-retire` without the moves having finished retires
nothing that a skipped row needs.

- **Fail closed**: a row under a deleted data key is `ErrSealed` ("data key … is not stored") - never served.
- **Backups**: a backup holds the old data keys and rows; retiring does not reach it. A leaked data key with a
  backup reads that backup's rows, as before.

## Enforcement & security

- Material is opened and sealed in memory only; nothing of it, of a token or of a data key is logged.
- Every move and every delete is compare-and-set; a race with the service loses nothing (the row is skipped, or
  the key kept).
- A tampered row is not laundered: its MAC must verify before it moves.
- No protocol change: versions and ETags are unchanged; the service's answers are the same.

## Testing

- The state suite: rows under three data keys (by age), `reseal` → every row under the active key, the same
  version and ETag, every read the same; `-retire` → the old keys gone, every row reads.
- Races: a row written between the read and the move (skipped, under the active key); a key made active by
  another replica during `-rotate`.
- A row whose MAC does not verify, and (SQL) one with none: skipped, named, exit 1, its key not retired.
- A key superseded less than `cache_ttl` ago: kept.
- Each SQL dialect and the Kubernetes store (envtest, as the store's tests); `memory` refused.

## Alternatives considered

- **Through `Update`** (each row written again): bumps every version - every client's ETag goes stale, every
  row looks edited. Rejected.
- **Re-sealing in the service, in the background**: a long-running job in every replica, its progress in the
  state. A command the operator runs when needed is enough.
- **Marking keys `retired_at` instead of deleting**: a marked key still opens; deleting is the point.

## Follow-ups

- Rollback detection (spec 014) is unchanged: an old row put back under a deleted key fails to open, under a
  kept one verifies.
