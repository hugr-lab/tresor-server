---
title: Data keys
---

# Data keys

**When**: rows lag behind the active data key, data keys no row uses pile up, or a data key leaked.

**Who**: the platform operator (the right to run the service's commands).

A data key seals the material and is wrapped by the KEK ([Encryption](../encryption.md)). A data key older than
`keys.data_key_max_age` (30 days) is replaced for new values. A value written once stays under the data key of its
day, and every data key stays stored, until `reseal` (spec 018) moves the rows and retires the keys.

## In view

- **The console's Service screen** (from `/admin/v1/data-keys`, the console's own API): how many data keys are
  stored, the active one's age, the oldest one's age. It says when a command is due:
  - rows under older data keys: `tresor-server reseal` moves them to the active one;
  - data keys used by no row: `tresor-server reseal -retire` deletes them.
- **The gauges**, counted every 10 minutes ([Observability](../observability.md#metrics)):
  `tresor.keys.data_keys`, `tresor.keys.oldest_age`, `tresor.keys.rows_behind`.

The view counts; it opens nothing.

## Resealing

1. Run `reseal -retire`:

   ```sh
   kubectl -n tresor create job --from=cronjob/<fullname>-reseal reseal-$(date +%Y%m%d%H%M)   # Kubernetes
   az containerapp job start -g <rg> -n <prefix>-reseal                                    # Container Apps
   tresor-server reseal -retire -config server.yaml                                         # a VM
   ```

   On SQLite, with the service stopped ([Running a command](commands.md#sqlite)).
2. Read its log: rows moved and skipped, each data key retired or kept, and why.

What it does:

- **Not a write**: each value is opened and sealed again under the same binding, its MAC made anew; its version,
  its times and its ETag stay. Every move is compare-and-set.
- **Only what verifies moves**: a row whose MAC does not verify, or (a SQL store) has none yet - `mac` first - is
  named and left, and the command exits `1`. Its data key is kept.
- **Minted tokens on a SQL store stay** under their data key: they go with their delegation grant, within hours;
  `-retire` keeps their data key until then. The Kubernetes store moves them too.
- **`-retire`** deletes a data key that is not the active one, that no row uses, and that has settled: an older
  key goes once the active one is older than `keys.cache_ttl` plus a minute. Each key kept is logged, with why.

### On a schedule

`maintenance.reseal.schedule` (a cron, e.g. `0 3 1 * *`) runs `reseal -retire` on that schedule: the rows follow
the data keys' rotation by age. Off by default; refused on SQLite. A job started by hand may overlap it: both
finish correctly. Container Apps: the recipe's jobs are manual only.

## A data key that leaked

A data key's plaintext was exposed; the KEK was not.

1. **A new data key, the rows moved to it**: `reseal -rotate -retire` (`<fullname>-reseal-rotate`,
   `<prefix>-reseal-rotate`).
2. **The replaced key deleted**: after `keys.cache_ttl` plus a minute (6 minutes by default), `reseal -retire`
   (`<fullname>-reseal`, `<prefix>-reseal`). The first run kept it: a write in flight may still have sealed under
   it.
3. **On a SQL store**, minted tokens stay under the leaked key until their delegation grants expire: run
   `reseal -retire` again after that. The log names the keys kept and why.

- **Backups** keep their own data keys: the leaked key still opens a backup taken before. Keep those backups as
  exposed, or delete them.
- Keep the replicas' clocks in sync (NTP): settling is measured by the data keys' times.

## Check

- The command exits `0`; its log counts the rows moved and the keys retired, none kept.
- The Service screen: no row under older data keys, no data key unused.
- `tresor.keys.rows_behind` is 0 at the next count.
- After a leak: the leaked key's id is logged as retired.

## Back

Nothing to undo: a reseal changes no value, version or ETag. A data key retired is gone; a row still under it is
refused (`500`), never read as empty - `-retire` deletes only a key no row uses. A backup taken before holds its
own data keys.
