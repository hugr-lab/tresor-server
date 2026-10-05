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
- An upgrade may ask for a step of its own. To the version that authenticates data keys (spec 003): the
  KEK's `sign`, and `tresor-server rewrap -tag-untagged` once - see [Encryption](encryption.md#the-root).
- An older binary refuses a database migrated by a newer one: roll forward, or restore the database.

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
  reason. A secret that does not open is a finding too.

  ```
  secret    lake      secret   invalid reference: no source for vault-us references is configured (material:)
  variable  region    value    invalid reference: ref+vault://secret/x#f is outside the allowlist (material.vault.allow)
  ```

- **No value** is printed. A reference that does not parse is named by its scheme only: its text may be a value
  written by mistake.
- **Exit**: `0` nothing to report, `3` findings, `1` an error.
- **It runs as the service**: the store, the KEK, and (with `-resolve`) the sources' rights. On Kubernetes:

  ```sh
  kubectl -n tresor exec deploy/tresor-tresor-server -- /tresor-server refs -config /etc/tresor/server.yaml
  ```

- It writes nothing. Opening a SQL store runs its migrations, as at a start.

## Backups

The database holds everything but the KEK. Back it up as any database. Without the KEK its material does not
open: keep the Key Vault key (purge protection), or the local key, as carefully as the backups.
