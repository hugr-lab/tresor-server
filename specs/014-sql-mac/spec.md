# Spec 014: a MAC on the SQL stores - who may use what, authenticated

- **Status**: implemented
- **Date**: 2026-10-08
- **Author**: hugr lab

## Summary

The Kubernetes store authenticates everything it does not seal with a MAC under a data key (spec 003): whoever can
write its resources cannot change who may use what without the KEK. The SQL stores (SQLite, PostgreSQL, SQL Server)
seal the material but keep the rest in plain columns, unauthenticated - "a setting later", spec 003 said. This is
that setting: `state.mac: true` gives the SQL stores the Kubernetes store's MAC, on secrets, variables, their
grants, delegation grants and minted tokens.

## Problem

A sealed value cannot be read or changed without the KEK, but the columns around it can, by anyone who can write
the database (a DBA, a stolen database credential, an application sharing the server):

- **a grant row added** (`role:me`, `use`) makes the service serve the material to that role;
- a secret's `scope` or `type` changed redirects which lookups find it; a delegation grant's actor or user
  changed acts for another person;
- a minted token's `failed` reason changed hides an error.

The data keys are authenticated by the KEK's root already (spec 003); the rows that say who may use them are not.

## Design

### The setting

```yaml
state:
  kind: postgres
  mac: true        # authenticate the rows: who may use what cannot change without the KEK
```

- Default `false` in this release: an upgrade changes nothing until the operator turns it on (below). The docs
  recommend it for every SQL store; a later major version may make it the default.
- `memory` has nothing at rest (refused there); `kubernetes` always has it (refused as redundant).

### What the MAC covers

The Kubernetes store's canonical encoding (`internal/state/canon`, moved there byte for byte, checked against the
old one), over the columns **as stored** - a JSON column's text, a time's microseconds - so a write and a read
encode the same bytes:

| Row | Covered |
| --- | --- |
| a secret or a variable | its name, kind (secret or variable), row id, type, provider, scope, redact keys, comment, owner, version, times, **its grants (id, principal, verbs) in order**, the data key id, the sealed bytes |
| a delegation grant | id hash, actor (owner, client, issuer), user (owner, JSON), expiries, data key id, the sealed subject |
| a minted token | the grant's id hash, the key's column (its hash: the AAD names the key itself), version, failure, data key id, sealed bytes |

- **A row with nothing sealed** (a delegation grant with no subject token, a minted token that failed) gets the
  active data key for its MAC, named in its key column.
- **Under a data key** (HMAC-SHA-256 with a key derived from it, as spec 003): the data key's own tag authenticates
  it under the KEK's root, so a MAC proves the row was written by the service.
- **The installation**: a random id made by the migration (0006), in the `installation` row, is part of every
  MAC: a row copied from another database under the same KEK does not verify. A store never makes another - a
  missing row is an error (a new id would refuse every row). It lives in the database a writer can change: a
  whole other database swapped in (its rows, keys and id) verifies, as a restored backup would; the Kubernetes
  store pins its id in configuration instead.
- **Grants live in their own table**: the secret's row carries the MAC over its grants too, so a grant's write
  rewrites the secret's MAC in the same transaction - a grant row added or changed behind the store no longer
  matches its secret's MAC.

### Reads

- A row whose MAC does not verify is `ErrSealed`: a read is refused, a list leaves it out (`tresor.state.left_out`,
  logged), as on the Kubernetes store - never served, never silently trusted.
- **A rollback is not detected**: an old row, MAC and all, put back verifies (spec 003 says the same of the
  Kubernetes store). The version inside the MAC stops a newer version's MAC on older columns, not the whole row.

### Turning it on

1. The migration (`0006_mac`) adds a nullable `mac` column to `secrets`, `variables`, `delegations`,
   `delegation_tokens`, and the `installation` table with its row. From the upgrade on, **every write carries a
   MAC, whatever the setting**: the setting turns the checks on. With the checks off, a MAC that does not verify
   is logged and counted, not refused - and the next write of the row gives it a valid one: the database is
   trusted as it is until the checks are on.
2. Once **every replica runs the new binary** (an older one rewrites rows and leaves their MAC stale; on SQLite,
   with the service stopped), `tresor-server mac -config …` (like `rewrap -tag-untagged`): gives every row with
   no MAC, or one that does not verify, a MAC - the operator vouches for the database as it is, once - and logs
   how many. A row it cannot (its data key gone) is named and skipped, and the command fails. Minted tokens with
   none are dropped instead: they are caches, minted again.
3. Set `state.mac: true`; deploy. Every read checks; a row with no MAC is refused like a wrong one.

Turning it off again stops the checks only; back on, nothing needs filling (writes kept their MACs).

### Rotation

- **A row's MAC is under the row's own data key** - the one its material is sealed with (`data_key_id`). On the
  SQL stores every write of a secret (a grant's change too) seals its material again under the active data key,
  and the MAC follows it.
- **The KEK's rotation and a move to another KEK** (`rewrap`, spec 011) rewrap the data keys and keep them: every
  MAC stays valid, nothing is recomputed (as on the Kubernetes store).
- **A data key retired by age** keeps verifying its rows: it stays stored, as it must for their sealed values.
- **Delegation grants and minted tokens** live hours: they are written under the active data key and purged.
- **The installation's id** never rotates; a backup restored elsewhere carries it.
- **A data key compromised** lets its holder read and forge the rows under it - MAC or not; rotation by age
  protects new rows only. Re-sealing every row under the active data key is a follow-up (below).

## Enforcement & security

- **Fail closed**: with `mac: true`, a missing or wrong MAC is `ErrSealed` - refused, never served.
- **What it stops**: a database writer adding or changing grants, scopes, owners, delegation grants, minted
  tokens' reasons. **What it does not**: deleting rows (a denial, not an escalation), or putting back an old row
  entire (a rollback).
- **The one-time `mac` pass** trusts the database at that moment: run it right after the upgrade, before anyone
  else could have written.
- Logs name rows and data keys, never values (as now).

## Testing

- The state suite (`internal/state/statetest`) on every SQL store with `mac: true`: everything passes as before.
- Integrity tests per dialect, as the Kubernetes store's: a grant row inserted, a scope changed, a delegation's
  actor changed, a token's failure changed, a row copied from another installation - each refused or left out; a
  rollback of a whole row - accepted (documented).
- The upgrade: a database at `0005` with rows, migrated, `tresor-server mac`, then `mac: true` - every row reads;
  a row written by hand afterwards with no MAC - refused.
- Conformance (tresor's suite) on PostgreSQL and SQL Server with `mac: true`.

## Alternatives considered

- **Sealing everything** (the descriptor and grants in the sealed blob): the lists and the grants' queries (by
  principal, for the console's Access screen) need the columns; a MAC keeps them readable.
- **Database row-level security or triggers**: the database's own access, which is exactly whom this is against.
- **On by default now**: an upgrade would refuse every existing row until the `mac` pass ran - an outage for
  whoever did not read the notes. A setting, then a default later.

## Follow-ups

- `state.mac: true` by default in a major version.
- Rollback detection (a monotonic counter under the KEK, or an append-only log) - for both stores.
- Re-sealing: every row's material and MAC moved to the active data key (a command), so old data keys can be
  retired - for both stores, encryption and MAC alike.
