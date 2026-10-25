# Spec 034: the docs before a release

- **Status**: implemented (#95; the owner, 2026-10-25: "пройтись по документации")
- **Date**: 2026-10-25
- **Author**: hugr lab

## Summary

A pass over the docs, the recipes and the chart's notes before a release: what was stale since 0.4, what the
code does differently from what a page says, and what a page left out. No code changes but the chart's notes and
the recipes' image defaults.

## Problem

Pages said ECS and Cloud Run jobs were not written though `commands.md` documents them; the recipes' image
defaults were v0.4.0; `mint+rule://` was "reserved" though implemented; the README and the overview were
Azure-only; several settings and readiness checks were missing or described wrongly.

## Design

- **Stale**: the "not written yet" lines (commands, the administration index, which now links the jobs);
  `mint+rule://` reserved; the README (status 0.7.5; the stores, the KEKs, the sources, variables, generated
  parameters, delegation by role, the chart and the three recipes, the console, conformance on all five stores;
  the license's parameters "in the LICENSE"); the overview's list and diagram; support (0.7.x; the cloud runs
  dated before 0.4.0, not re-run since); security's examples at v0.7.5.
- **The recipes**: `image` (ECS) and `image_tag` (Cloud Run) default to v0.7.5, and Development's new release
  section says they move with each release. The READMEs: `image_tag` for the version on Cloud Run, the
  `prefix` and `material_prefixes` limits, the ECS task role `<prefix>-task-<region>`, the Container Apps
  probes and the `dsn` output.
- **Configuration**: `state.auth: vault` and a `state.vault` row (`set_role` required on PostgreSQL, refused on
  SQL Server); `material.gcp.allow` takes project ids, never numbers; every field of `dynamic.identities` by
  kind; an actor's role issuer one of `issuers`; `material.aws` needs `aws.region`; CORS exposes `X-Request-Id`.
- **Generated parameters**: `mint+rule://` and `${rule://…}` in the syntax table; the "reserved" line gone;
  `GET /admin/v1/logins` lists logins (no console screen does).
- **Readiness**: the `tls` check (degraded: a new pair that failed to load, the certificate in service expired);
  the `exchange` check exists only for a `client_auth` other than `secret`, and every `mint+exchange://` depends
  on it, not only `token_exchange` secrets (operations, incidents, token exchange).
- **Token exchange**: the snippets nested under `issuers[]`; `awskms` and `gcpkms` rows.
- **References**: named sources of all four kinds (`vault`, `azkv`, `aws`, `gcp`), their connections and
  allowlists; `cache_ttl` for every source but `ref+k8s`.
- **The audit**: `changes` drops successful inspections too (observability); the console's data keys and logins
  views are not audited, the lists neither.
- **The CRDs** applied from the pulled chart (`helm pull … --untar`), not a local `crds/` (upgrading,
  Kubernetes, backup and restore, the chart's README and notes); a restore's `helm upgrade` names its chart
  version; upgrading names the ECS and Cloud Run image variables, and 0.5.1 and 0.7.1 need nothing.
- **The chart**: `values.yaml` documents `nameOverride`, `fullnameOverride`, and `<fullname>-reseal`; the notes'
  plain-http hint reads the rendered configuration, so it shows with the chart's default offload too.
- Smaller: the encryption root for AWS KMS and Cloud KMS; `auth: password` beside `password_ref` on Kubernetes;
  the console's account menu (`whoami`'s `name`) and an actor's issuer on the Service screen.

## Enforcement & security

Docs only, but the chart's notes and the recipes' defaults. No protocol change.

## Testing

`npm run build` of the site (broken links fail it); `helm lint --strict`, and `helm install --dry-run` of the
notes with and without `tlsSecret`.

## Follow-ups

- The console's **Revoke my sessions on servers** sends `DELETE /v1/delegations` with no filter: for an
  administrator (every console user) the service answers `422` ("name an actor or a subject"). Not documented
  until fixed.
