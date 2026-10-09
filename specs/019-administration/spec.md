# Spec 019: administration - who runs what, how: the commands as jobs, the runbooks, the keys in view

- **Status**: draft
- **Date**: 2026-10-09
- **Author**: hugr lab

## Summary

The service runs itself; what it needs from people - a configuration change, a KEK's rotation, an upgrade with a
step of its own, a data key that leaked - is spread over pages written per feature, and the commands that do it
(`rewrap`, `mac`, `refs`, `reseal`) have one documented way to run: `kubectl exec`. This gives the operator one
place: who does what, a runbook per task, and a supported way to run each command on each platform - as a job
with the service's own identity, never a shell on a host. The console shows the data keys' state, so the
operator knows when a command is due.

## Problem

- **No shell, by design**: the image is distroless and runs as non-root. A command runs as the service - its
  configuration, its store, its KEK rights, its cloud identity - and nothing else may hold those.
- **`kubectl exec`** needs `pods/exec`: the pod's files (a local KEK, an identity's token) - the KEK's power,
  given as a debugging right. On Container Apps and Cloud Run, exec is not the platform's way; a job is.
- **SQLite on Kubernetes**: `mac` and `reseal` need the service stopped (its lease), and then there is no pod to
  exec into; its volume is ReadWriteOnce. A cluster can run a database: SQLite there is not recommended.
- **Runbooks are scattered**: the KEK's rotation is in Encryption, the MAC's upgrade in State, `refs` in
  Operations; a configuration change, a leaked data key, the service's IdP credential rotated, a restore - not
  written as procedures at all.
- **When is a command due?** Nothing shows how many data keys there are, how old, or how many rows are not
  under the active one.

## Design

### Roles

| Who | Does | Through |
| --- | --- | --- |
| **The platform operator** | deploys, configures, rotates and moves the KEK, runs the commands, restores | the platform (Helm, Bicep, the cluster's or the cloud's rights) |
| **A secrets administrator** (`policy.admins`) | manages secrets, variables, references, grants | the API, the console |
| **A role** | uses what it is granted | DuckDB |

Running a command is acting as the service: it is the platform operator's, and the right to run one (to create
a Job, to start a Container Apps job) is the KEK holder's right - granted as such. No maintenance goes through
the API: a secrets administrator manages secrets, not keys (tresor specs/009: admins manage, roles use).

### The commands as jobs

- **Kubernetes (the chart)**: a suspended CronJob per command, `<release>-reseal`, `-reseal-rotate`, `-rewrap`,
  `-refs`, `-mac` - the service's image, ServiceAccount, configuration, volumes and environment, `restartPolicy:
  Never`, no retries, a deadline. Run one:

  ```sh
  kubectl -n tresor create job --from=cronjob/<release>-reseal reseal-$(date +%Y%m%d%H%M)
  kubectl -n tresor logs -f job/reseal-…
  ```

  The operator needs `create` on `jobs` in the namespace (not `pods/exec`); the chart documents it as the KEK's
  right.
  - `maintenance.reseal.schedule` (off by default): `reseal -retire` on a schedule, e.g. monthly - the rows
    follow the data keys' rotation by age, and old data keys go.
  - `maintenance.refsBeforeUpgrade` (off by default): `refs` with the new configuration as a `pre-upgrade` hook;
    a finding (exit 3) stops the upgrade before a reference is stranded.
  - SQLite: the chart's NOTES warn that it is not recommended on a cluster; `mac` and `reseal` there need
    `replicas: 0` first (a runbook).
- **Azure Container Apps (the Bicep recipe)**: a Container Apps job, manual trigger, the app's image, managed
  identity and environment; its command and arguments chosen at the start:

  ```sh
  az containerapp job start -g <rg> -n <prefix>-maint --command /tresor-server --args reseal -retire
  ```

  Its logs go to the environment's Log Analytics.
- **Docker, a VM**: `docker run --rm` with the service's image and its `TRESOR_*` environment, or the binary as
  the service's user with its configuration file.
- **AWS (ECS run-task), GCP (Cloud Run jobs)**: written with their live checks (spec 012), at the end.

### The keys in view

`/admin/v1/service` (the console's own API, not the protocol) and the Service screen gain the data keys: how
many are stored, the active one's age, the oldest one's age, and how many rows are under another one than the
active. Counted when the screen asks (a count, or on Kubernetes a list - no row is opened) and, for the
metrics, every 10 minutes: `tresor.keys.data_keys`, `tresor.keys.oldest_age`, `tresor.keys.rows_behind` (the
Observability page). The Service screen says when a command is due: "rows under older data keys: run reseal";
"data keys no row uses: reseal -retire".

### The administrator's guide

A section of the site, **Administration**, one page per task, each: when, who, the steps per platform, how to
check it worked, how to go back:

1. **Roles and rights**: the table above; what to grant on Kubernetes, Azure, Vault.
2. **Running a command**: the jobs above, per platform; exit codes.
3. **Changing the configuration**: the configuration is read at start; `refs` with the new configuration
   first; deploy (the chart rolls the pods on a change); readiness; back.
4. **An issuer or a material source** added, renamed, removed (`refs`).
5. **The KEK**: rotating it (per kind), moving to another (spec 011), a version retired.
6. **Data keys**: the rotation by age; `reseal`; a data key that leaked (`-rotate`, then `-retire` minutes
   later; backups).
7. **The service's own credentials**: the IdP client's secret or federated credential (spec 017's 503s), the
   database password reference, a Vault login.
8. **Upgrading**: migrations, the steps a version asks for (`rewrap -tag-untagged`, `mac` then `state.mac`), the
   release notes.
9. **Backup and restore**: what to keep with the database (the KEK, the installation id); a restore and its
   checks.
10. **Incidents**: the service unready (which check), a KEK unreachable, rows refused (`left_out`), the store
    held (SQLite).

The feature pages keep the reference; the guide links to them, and their own procedure sections move into it.

## Enforcement & security

- No shell, no SSH, no maintenance endpoint: a command runs only with the platform's job rights, as the service.
- A job's logs are the service's: names and counts, never a value.
- The keys' view counts; it opens nothing.

## Testing

- Chart: `helm template` with each `maintenance` setting; the kind check runs `kubectl create job --from` for
  `reseal` and `refs` and checks their exit (the chart's CI, kind).
- Bicep: the job builds (`az bicep build`, CI); live with the next Azure run.
- `/admin/v1/service`: the counts on every store (the state suite), the Service screen's notices (Vitest).
- The guide: the docs site builds; each runbook's commands are the ones the CLI accepts (a test of the examples'
  command lines against `parseArgs`).

## Alternatives considered

- **`kubectl exec` as the way**: kept as a fallback (`refs` beside a serving replica), not the documented path -
  `pods/exec` is a broader right than a job's, and it does not work for SQLite or the job platforms.
- **Maintenance through the API or the console**: mixes the secrets administrator's role with the KEK's; long
  runs inside the service. Rejected.
- **The service resealing on its own, in the background**: spec 018 rejected it; a schedule (CronJob) gives the
  same with the operator in control.

## Follow-ups

- AWS and GCP jobs, with their live checks.
- Moving from SQLite to a SQL server (an export and import command), should anyone need it.
