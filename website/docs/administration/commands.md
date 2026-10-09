---
title: Running a command
---

# Running a command

The binary is the service and its commands. A command runs as the service - its image, configuration, store,
KEK rights and identity - as a job, never in a shell.

## The commands

```
tresor-server [rewrap | refs | mac | reseal] [flags] [-config <file>]
```

| Command | Does |
| --- | --- |
| (none) | serves |
| `rewrap` | wraps every data key under the KEK's current version, and off a `keys.previous` KEK ([The KEK](kek.md)) |
| `rewrap -tag-untagged` | once, at the upgrade to authenticated data keys: tags the data keys that have none ([Upgrading](upgrading.md)) |
| `refs` | lists the stored references the configuration would not admit; `-resolve` reads each one too ([Operations](../operations.md#checking-references)) |
| `mac` | SQL stores: gives every row with no MAC, or a stale one, a MAC - once, before `state.mac: true` ([Upgrading](upgrading.md)) |
| `reseal` | moves every row to the active data key; `-rotate` makes a new active one first; `-retire` then deletes the data keys nothing uses ([Data keys](data-keys.md)) |

- The configuration comes from `-config <file>`, then `TRESOR_CONFIG`, then the `TRESOR_*` variables, as the
  service's ([Configuration](../configuration.md)). The command comes first: `tresor-server -config x rewrap` is a
  usage error.
- **The service's own version.** `rewrap`, `mac` and `reseal` open the store as the service does: a newer binary
  would migrate the database. `refs` never migrates: an older or newer schema is refused.
- **Beside a serving replica**: every change is compare-and-set. On SQLite, stop the service first: `mac` and
  `reseal` need the database's lease (and refuse while a replica holds it); `refs` takes none, but on a cluster
  its volume is the serving pod's.
- **The log**: names and counts, never a value. `refs` prints its findings on stdout.

| Exit | |
| --- | --- |
| `0` | done; for `refs`, nothing to report |
| `1` | an error: the log says what (a row or data key named, the store or the KEK unreachable) |
| `2` | a usage error: an unknown command or flag |
| `3` | `refs`: findings |

## Kubernetes (the chart)

The chart makes a suspended CronJob per command, with the service's image, ServiceAccount, configuration,
volumes and environment ([Kubernetes](../kubernetes.md#the-commands-as-jobs)). `<fullname>` is the one the
chart's NOTES print.

| CronJob | Runs |
| --- | --- |
| `<fullname>-reseal` | `reseal -retire` |
| `<fullname>-reseal-rotate` | `reseal -rotate -retire` |
| `<fullname>-rewrap` | `rewrap` |
| `<fullname>-refs` | `refs -resolve` |
| `<fullname>-mac` | `mac` (SQL stores only) |

```sh
kubectl -n tresor create job --from=cronjob/<fullname>-reseal reseal-$(date +%Y%m%d%H%M)
kubectl -n tresor logs -f job/reseal-…
kubectl -n tresor get job reseal-…                     # Complete, or Failed
kubectl -n tresor get pods -l job-name=reseal-… \
  -o jsonpath='{.items[0].status.containerStatuses[0].state.terminated.exitCode}'
```

- A job is not retried (`backoffLimit: 0`), ends at `maintenance.activeDeadlineSeconds` (an hour), and is kept a
  week.
- `rewrap -tag-untagged` and `refs` without `-resolve` have no CronJob. To run one, render a job from the nearest
  CronJob, change its `args`, and create it - a manual step:

  ```sh
  kubectl -n tresor create job --from=cronjob/<fullname>-rewrap tag-untagged --dry-run=client -o yaml > job.yaml
  # args: ["rewrap", "-tag-untagged", "-config", "/etc/tresor/server.yaml"]
  kubectl -n tresor create -f job.yaml
  ```

### SQLite

SQLite on a cluster is not recommended. Its volume is ReadWriteOnce and the serving pod's, and `mac` and
`reseal` need its lease: every command needs the service scaled to 0 first, and no schedule runs.

```sh
kubectl -n tresor scale deploy/<fullname> --replicas=0
kubectl -n tresor create job --from=cronjob/<fullname>-reseal reseal-$(date +%Y%m%d%H%M)
kubectl -n tresor logs -f job/reseal-…
kubectl -n tresor scale deploy/<fullname> --replicas=1
```

The service is down meanwhile. A command started with the service up stops with "the SQLite database is held by
a serving replica".

### `kubectl exec`: a fallback

`refs` takes no lease and writes nothing: it can run beside a serving replica.

```sh
kubectl -n tresor exec deploy/<fullname> -- /tresor-server refs -config /etc/tresor/server.yaml
```

A fallback only: `pods/exec` is a broader right than a job's (the pod's files), and the job platforms have no
exec.

## Azure Container Apps (the recipe)

The recipe makes a manual job per command, with the app's image, managed identity and settings
([Azure Container Apps](../azure-container-apps.md#the-commands-as-jobs)):

| Job | Runs |
| --- | --- |
| `<prefix>-reseal` | `reseal -retire` |
| `<prefix>-reseal-rotate` | `reseal -rotate -retire` |
| `<prefix>-rewrap` | `rewrap` |
| `<prefix>-refs` | `refs -resolve` |
| `<prefix>-mac` | `mac` |

```sh
az containerapp job start -g <rg> -n <prefix>-reseal
az containerapp job execution list -g <rg> -n <prefix>-reseal -o table   # Succeeded, or Failed
```

- The logs go to the environment's Log Analytics.
- Start a job with no arguments of your own: a start's arguments replace the container's template, its settings
  with it.
- No retry, an hour's timeout.
- `rewrap -tag-untagged` and `refs` without `-resolve` have no job: not supported by the recipe.

## Docker

The service's image, tag and settings: the same environment, the same mounted configuration and volumes, the same
identity.

```sh
docker run --rm --env-file <the service's env file> ghcr.io/hugr-lab/tresor-server:<the service's tag> reseal -retire
docker run --rm -v <the configuration's dir>:/etc/tresor:ro -v <the data volume>:<its path> \
  ghcr.io/hugr-lab/tresor-server:<the service's tag> refs -resolve -config /etc/tresor/server.yaml
```

On SQLite, stop the service's container first for `rewrap`, `mac` and `reseal` (`mac` and `reseal` refuse
otherwise).

## A VM

The binary, as the service's user, with its configuration file and its environment (a local KEK's variable, a
password's):

```sh
sudo -u <the service's user> tresor-server reseal -retire -config /etc/tresor/server.yaml
```

On SQLite, stop the service first for `rewrap`, `mac` and `reseal`, and start it after.

## AWS, GCP

ECS run-task and Cloud Run jobs are not written yet (spec 012): they come with their live checks.
