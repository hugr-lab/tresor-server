# Spec 027: the state's database credentials from a Vault database secrets engine

- **Status**: implemented (#79; the owner, 2026-10-21; asked by the duckdb-acl session for hugr-platform's umbrella chart)
- **Date**: 2026-10-21
- **Author**: hugr lab

## Summary

`state.auth: vault`: the service logs in to its PostgreSQL or SQL Server with a user and a password a Vault/OpenBao
database secrets engine makes for it - no password stored, a user per lease. (A KV field through `password_ref:
ref+vault://…` worked already, since 0.2.)

## Design

- **Config**: `state.auth: vault` and `state.vault: {mount, role, source?}` - through the `vault:` connection, or a
  named vault source's. No password setting; the DSN's user is replaced by the engine's.
- **Login** (`sqlstore.VaultLogin`, a `UserLogin`): `GET <mount>/creds/<role>` gives a user, a password and the
  lease's length. New connections take them while one made with them ends (30-minute connections, plus a 2-minute
  margin) before the lease does; then new credentials. Old leases are left to expire, never revoked: a connection
  still open with them keeps working until it closes. A lease shorter than 32 minutes is refused (raise the role's
  `default_ttl`).
- PostgreSQL's `BeforeConnect` and SQL Server's connector take the user too.
- **Ownership** (PostgreSQL): each lease is another user, so the tables cannot be a user's. `state.vault.set_role`
  (required on PostgreSQL) names a group role every lease's user is granted (`IN ROLE` in the engine's creation
  statements); the service runs `SET ROLE` on each new connection, so the migrations' objects are the group's, the
  next lease's user reads them, and Vault drops an expired user cleanly. SQL Server's objects are the schema's: a
  database role in the creation statements; no `set_role` there.

## Enforcement & security

The credentials are never logged (the path and the lease's length only). An unreadable lease, or an empty user or
password, fails the connection - never an empty login.

## Testing

Go: the rotation's arithmetic; on CI, a real OpenBao and HashiCorp Vault each with a PostgreSQL database secrets
engine: the store opens and migrates as a lease's user under the group role (`session_user`, `current_user`), and a
later lease's user reads what the first wrote. Config: the refusals.
