---
title: Operations
---

# Operations

## Health

| Route | Answers |
| --- | --- |
| `GET /healthz` | 200 while the process is up. |
| `GET /readyz` | 200 when every check passes; 503 otherwise. |

The checks run in the background every 30 s, so a probe never calls a database, a vault or an identity
provider itself:

- **state**: the store answers; on SQLite, this replica holds the lease;
- **keys**: the KEK wraps and unwraps a throwaway key;
- **issuer ...**: one per issuer, its discovery and signing keys. An issuer that answered once and is down
  now is `degraded`, not `unavailable`: its keys are cached, and one IdP's outage must not take every
  replica out.

`/readyz` names each check's status (`ok`, `degraded`, `unavailable`, `not checked yet`), never an error's
text; the error goes to the log. On SIGTERM the service turns unready first, then shuts down.

## Logs

Text lines (`log/slog`) on stderr:

- one line per request: method, path, status, the caller's subject, the time taken; a delegation grant's id
  is cut from its path;
- each reference resolved: the secret, the reference, the version;
- the configuration's variables taken from the environment (names only);
- readiness changes, store failures, refused tokens (the reason, never the token).

Never logged: material, tokens, data keys, a grant's id, a configuration value.

## Replicas

- **PostgreSQL, SQL Server**: run as many as you like. Every write is compare-and-set, delegation grants
  are in the store, and a minted token is renewed by one replica at a time.
- **SQLite**: one replica serves; another waits for the lease (see [State stores](state.md)).

## Upgrading

- Migrations run at start, one replica at a time (a lock in the database).
- An older binary refuses a database migrated by a newer one: roll forward, or restore the database.

## Backups

The database holds everything but the KEK. Back it up as any database. Without the KEK its material does not
open: keep the Key Vault key (purge protection), or the local key, as carefully as the backups.
