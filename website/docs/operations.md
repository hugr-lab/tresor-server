---
title: Operations
---

# Operations

## Health

| Route | Answers |
| --- | --- |
| `GET /healthz` | 200 while the process is up. |
| `GET /readyz` | 200 unless a check is `unavailable` or `not checked yet` (`degraded` is still ready); 503 then, and while shutting down. |

The checks run in the background every 30 s, so a probe never calls a database, a vault or an identity
provider itself:

- **state**: the store answers; on SQLite, this replica holds the lease;
- **keys**: the KEK wraps and unwraps a throwaway key; **keys.previous[i]**: each previous KEK, during a move;
- **issuer ...**: one per issuer, its discovery and signing keys. An issuer that answered once and is down
  now is `degraded`, not `unavailable`: its keys are cached, and one IdP's outage must not take every
  replica out.
- **exchange ...**: one per issuer with `exchange`, the service's client assertion. A failure is `degraded`:
  only `token_exchange` secrets depend on it.

What each check's failure means: [Incidents](administration/incidents.md#the-service-unready).

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

Migrations run at start, one replica at a time; an older binary refuses a database a newer one migrated. The
steps a version asks for (`rewrap -tag-untagged`, `mac` then `state.mac`): [Upgrading](administration/upgrading.md).

## Checking references

`tresor-server refs` lists the stored references (in secrets and variables) that the configuration would not
resolve (spec 009):

```sh
tresor-server refs -config server.yaml            # the parse and the allowlists, as at a fetch
tresor-server refs -config server.yaml -resolve   # and a read of each one
```

- **Before a configuration change**: run it with the new configuration against the live store. A source
  renamed or removed, or an allowlist narrowed, strands references silently otherwise: they fail at their
  next fetch.
- **The output**, one line per finding, tab-separated: `secret` or `variable`, the name, the parameter, the
  reason. A secret that does not open (sealed) is a finding too; the store or the KEK unreachable stops the
  run.

  ```
  secret    lake      secret   invalid reference: no source for vault-us references is configured (material:)
  variable  region    value    invalid reference: ref+vault://secret/x#f is outside the allowlist (material.vault.allow)
  ```

- **No value** is printed. A reference that does not parse is named by its scheme only: its text may be a value
  written by mistake.
- **Exit**: `0` nothing to report, `3` findings, `1` an error, `2` a usage error.
- **It runs as the service**: the store, the KEK, and (with `-resolve`) the sources' rights - as a job:
  `<fullname>-refs` on the chart, `<prefix>-refs` on Container Apps ([Running a command](administration/commands.md)).
  With the new configuration before a change: [Changing the configuration](administration/configuration.md).

- **It writes nothing**, beside a serving replica:
  - a SQL store is not migrated: run the service's own version, or the schema is refused;
  - SQLite: no lease taken, a read-only connection;
  - `-resolve` bounds each read to 30 seconds.

## Backups

The database holds everything but the KEK: keep the KEK as carefully as the backups. What to keep, a restore and
its checks: [Backup and restore](administration/backup-restore.md).
