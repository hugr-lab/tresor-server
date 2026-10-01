---
title: State stores
---

# State stores

The state store keeps the secrets, their grants, and the delegation grants (servers acting for users).
Material in it is only ever sealed: see [Encryption](encryption.md).

| Kind | Replicas | For |
| --- | --- | --- |
| `memory` | one | tests; everything is lost when the process ends |
| `sqlite` | one | a laptop, a VM, docker compose |
| `postgres` | several | PostgreSQL, Azure Database for PostgreSQL |
| `sqlserver` | several | SQL Server, Azure SQL |

## What every store does

- **Every write is compare-and-set** on the secret's version and its row. A write read before another
  replica's change is run again on the new secret; it never overwrites it.
- **Names are compared exactly**, in every store. A write (a secret, a grant) is refused (`422`) when its
  name or grant id is empty, longer than 200 characters, not UTF-8, begins or ends with a space, or holds a
  control character.
- **A list or a descriptor opens no material.** Only a read with `use` opens a secret's params. A secret
  whose params do not open fails that read with `500 service_error` (an operator must act; a KEK that does
  not answer is `503`, try later); an administrator may still delete it.
- **Delegation grants live in the store**, for every replica to honour. A grant's id is never stored: rows
  are keyed by its SHA-256. The user's token and the tokens minted for them are sealed. Expired grants are
  purged every minute.
- **Migrations are embedded** and applied at start. A database migrated by a newer binary is refused, never
  written.

## SQLite

```yaml
state: {kind: sqlite, path: /data/tresor.db}
keys: {kind: local, key_env: TRESOR_KEK}
```

- Pure Go (no cgo). WAL, foreign keys, immediate write transactions.
- The file is created `0600`.
- **One replica serves.** It holds a lease row in the database and renews it every 5 s (15 s expiry).
  Another replica waits, serving nothing and not ready, and takes over when the first stops. A row, not a
  file lock: file locks are not reliable on network shares.
- The holder stops serving at its own deadline, 5 s before the expiry it wrote: a paused process stops
  before another may take over.

## PostgreSQL

```yaml
state:
  kind: postgres
  dsn: host=corp-pg.postgres.database.azure.com user=tresor-id dbname=tresor sslmode=verify-full
  auth: entra
azure: {identity: managed}
```

- **Several replicas.** A transaction's lock is `pg_advisory_xact_lock`; deadlocks and serialization
  failures are run again.
- **The DSN never carries a password.** The login gives one for each new connection:
  - `auth: entra`: the service's Entra token, for Azure Database for PostgreSQL. The database role is the
    managed identity's;
  - `auth: password`: from `password_env` or `password_file`, read again for each connection - a rotation
    needs no restart.
- **Off this machine, `sslmode=verify-full` is required.** The password (a token) goes over the
  connection. pgx's default, `prefer`, falls back to plain text; `require` checks no certificate.
- The pool: 10 connections unless `max_open_conns` says otherwise, 30-minute connections, a 10 s connect
  timeout.

## SQL Server, Azure SQL

```yaml
state:
  kind: sqlserver
  dsn: sqlserver://corp-sql.database.windows.net?database=tresor&encrypt=true
  auth: entra
azure: {identity: managed}
```

- **Several replicas.** A transaction's lock is `sp_getapplock`; a deadlock victim is run again.
- **On Azure SQL, an access token**: the managed identity logs in with no password at all. The database
  user is created `FROM EXTERNAL PROVIDER`, or the identity is the server's Entra administrator.
- **Off this machine, `encrypt=true`** (or `strict`) with the certificate checked is required.
- Compared texts are `COLLATE Latin1_General_100_BIN2`: the default collation compares without case, and
  names are compared exactly.
