---
title: Administration
---

# Administration

What the service needs from people, one page per task (spec 019). Each runbook says when, who, the steps per
platform, how to check, and how to go back. The feature pages keep the reference; the runbooks link to them.

## Roles and rights

| Who | Does | Through |
| --- | --- | --- |
| **The platform operator** | deploys, configures, rotates and moves the KEK, runs the commands, restores | the platform: Helm, Bicep, the cluster's or the cloud's rights |
| **A secrets administrator** (`policy.admins`) | manages secrets, variables, references, grants | the API, the [console](../console.md) |
| **A role** | uses what it is granted | DuckDB |

- **Running a command is acting as the service**: its configuration, its store, its KEK rights, its cloud
  identity. The right to run one (to create a Job, to start a Container Apps job) is the KEK holder's right.
  Grant it as such.
- **No shell, no SSH**: the image is distroless and runs as non-root. A command runs as a job with the service's
  own identity, never in a shell on a host.
- **No maintenance through the API**: a secrets administrator manages secrets, not keys (admins manage, roles
  use). Nothing in `/admin/v1` or the console runs a command.

## What to grant

### Kubernetes

The operator needs, in the service's namespace, the rights to start a command's job and read its log:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: tresor-operator, namespace: tresor}
rules:
  - {apiGroups: [batch], resources: [cronjobs], verbs: [get]}              # create job --from=cronjob/…
  - {apiGroups: [batch], resources: [jobs], verbs: [create, get, list, watch]}
  - {apiGroups: [""], resources: [pods, pods/log], verbs: [get, list, watch]}   # kubectl logs job/…
  # scaling to 0 (SQLite, a restore), rollout restart and status:
  - {apiGroups: [apps], resources: [deployments], verbs: [get, list, watch, patch]}
  - {apiGroups: [apps], resources: [deployments/scale], verbs: [get, patch, update]}
```

A cluster with the `OwnerReferencesPermissionEnforcement` admission plugin also needs `update` on
`cronjobs/finalizers` (`--from` sets the Job's owner).

Each of these rights, in that namespace, is as strong as `create jobs` - whoever has one acts as the service:

- `create` on pods, jobs, cronjobs, deployments (any workload that can name the service's ServiceAccount);
- `update` or `patch` on an existing workload - the chart's CronJobs included: their image, their arguments,
  their `suspend`;
- `update` or `patch` on the service's ConfigMap (its allowlists, its policy);
- `pods/exec` on the service's pods (their files: a local KEK, an identity's token);
- `create` on `serviceaccounts/token` for the service's ServiceAccount;
- `impersonate` of that ServiceAccount;
- `get`, `list` or `watch` on the namespace's Secrets (a local KEK, a client secret, a password: a list returns
  their contents).

Keep them to the platform's operators. The chart's NOTES say the same. On the Kubernetes store, writing the
`tresor` resources is the service's alone: the [admission policy](../kubernetes.md#the-store) refuses anyone
else.

### Azure Container Apps

- **Who may start the jobs** (`<prefix>-reseal`, `-reseal-rotate`, `-rewrap`, `-refs`, `-mac`) acts as the
  service's managed identity. Give the start (`Microsoft.App/jobs/start/action`) on those jobs to the operators
  only.
- **Who may change the app or a job** (its image, its arguments, its settings) acts as the identity too.
- **Who may assign the identity** (`Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`) to a resource
  of their own acts as it.
- **Reading a job's executions** (`az containerapp job execution list`) needs read on the jobs.
- **Who may read the environment's Log Analytics** reads the jobs' logs: names and counts, never a value.

### OpenBao and Vault

- **The service's policy** names only what it uses: see [OpenBao and Vault](../vault.md#the-policy). `hmac` on
  the KEK is the service's alone: whoever holds it computes the root.
- **The operator** rotates the Transit key and retires its versions (`update` on
  `transit/keys/<key>/rotate` and `transit/keys/<key>/config`). Never `hmac` on it.
- **Admins** write `ref+vault` references; the service reads them, within `material.vault.allow`.

### AWS, GCP

The KMS keys' MAC operation (`kms:GenerateMac`, a MAC key's `useToSign`) is the service's alone: see
[AWS](../aws.md#the-kek-two-keys) and [GCP](../gcp.md#the-kek-a-key-and-a-mac-version). Jobs on ECS and Cloud
Run are not written yet (spec 012).

## The runbooks

1. [Running a command](commands.md): the jobs per platform, the exit codes.
2. [Changing the configuration](configuration.md): `refs` first, deploy, readiness, back.
3. [An issuer or a material source](issuers-and-sources.md): added, renamed, removed.
4. [The KEK](kek.md): rotating it per kind, moving to another, retiring old versions.
5. [Data keys](data-keys.md): their rotation by age, `reseal`, a data key that leaked.
6. [The service's own credentials](credentials.md): the IdP client, the database password, the Vault login,
   the cloud identity.
7. [Upgrading](upgrading.md): migrations, the steps a version asks for.
8. [Backup and restore](backup-restore.md): what to keep with the database, a restore and its checks.
9. [Incidents](incidents.md): the service unready, a KEK unreachable, rows refused, the store held, the IdP
   refusing the service.
