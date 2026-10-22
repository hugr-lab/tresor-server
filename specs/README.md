# Specs

One **lightweight spec per change**: a short, honest document so decisions are written down and
reviewable. Same process as tresor's (`tresor/specs/README.md`).

1. Before (or alongside) a change, create `specs/NNN-slug/spec.md` from `TEMPLATE.md`.
2. A protocol change is specced in tresor first (`website/docs/protocol.md` is normative there), then here.
3. Keep the spec current; `Status: implemented` when it lands; reference it in the commit/PR.
4. Supersede, don't rewrite.

Research lives in the local, gitignored `design/` folder.

## Index

| Spec | Title | Status |
| --- | --- | --- |
| [001](001-architecture/spec.md) | tresor-server - state stores, KEK, material by reference, deployment, phases | implemented |
| [002](002-phase1-azure-mvp/spec.md) | phase 1 - the Azure MVP | implemented |
| [003](003-kubernetes/spec.md) | phase 3 - Kubernetes: the CRD store, ref+k8s, workload identity, the Helm chart | implemented |
| [004](004-variables/spec.md) | variables (tresor spec 018): a second namespace on every store, sealed | implemented |
| [005](005-observability/spec.md) | observability: the audit (stdout, OTLP), spans under tresor's trace, metrics | implemented |
| [006](006-exchange-without-secret/spec.md) | token exchange without a client secret; ZITADEL, for a stack with no Azure | implemented |
| [007](007-vault/spec.md) | OpenBao and HashiCorp Vault: the KEK in Transit, ref+vault, signing, no static secret | implemented |
| [008](008-named-sources/spec.md) | named material sources: ref+<name>://, more instances of a kind, each its own connection | implemented |
| [009](009-refs-command/spec.md) | `tresor-server refs`: the stored references the configuration would not resolve | implemented |
| [010](010-console/spec.md) | the management console: /ui/, /admin/v1, a microfrontend for the hugr platform | implemented |
| [011](011-kek-migration/spec.md) | moving to another KEK: `keys.previous` (read only), then `rewrap` | implemented |
| [012](012-aws-gcp/spec.md) | phase 4 - AWS and GCP: KMS as the KEK, Secrets Manager and Secret Manager as sources, no static secret | implemented |
| [013](013-entra-on-behalf-of/spec.md) | Entra On-Behalf-Of for `token_exchange` secrets: `exchange.grant: on_behalf_of` | implemented |
| [014](014-sql-mac/spec.md) | a MAC on the SQL stores: `state.mac`, who may use what authenticated | implemented |
| [015](015-policy-package/spec.md) | `internal/policy`: the permission model in a package of its own (a refactor) | implemented |
| [016](016-platform-contract/spec.md) | the console in the hugr platform: the microfrontend's contract, version 1 | implemented |
| [017](017-service-client-refused/spec.md) | the service's own client refused by the IdP: `503`, never stored in a grant | implemented |
| [018](018-reseal/spec.md) | `tresor-server reseal`: every row moved to the active data key, old data keys retired | implemented |
| [019](019-administration/spec.md) | administration: the commands as jobs, the runbooks, the data keys in view | implemented |
| [020](020-gcp-cloud-run/spec.md) | a GCP recipe: Cloud Run, Cloud SQL by Private Service Connect, in Terraform | implemented |
| [021](021-aws-ecs/spec.md) | an AWS recipe: ECS on Fargate, RDS by IAM in private subnets, in Terraform | implemented |
| [022](022-release-0.4/spec.md) | release 0.4.0: tresor's browsers (CORS), the MAC on by default, signed artifacts | implemented |
| [023](023-dynamic-params/spec.md) | dynamic parameters: any type, a value made on each read; service logins | implemented |
| [024](024-generated-variables/spec.md) | generated values in variables, as in secrets | implemented |
| [025](025-docs-ionos/spec.md) | the docs on hugr-lab.com too (IONOS), legal links on both | implemented |
| [026](026-cluster-install/spec.md) | an unattended install: the cluster's own accounts, namespaceOverride | implemented |
| [027](027-vault-database/spec.md) | the state's database credentials from a Vault database secrets engine | implemented |
| [028](028-chart-config-tpl/spec.md) | the chart's config through tpl (configTemplate) | implemented |
| [029](029-tls-reload/spec.md) | the TLS certificate read again when it changes | implemented |
| [030](030-whoami-name/spec.md) | whoami names the person; an IdP's own roles left out | implemented |
| [031](031-actor-role/spec.md) | a delegation actor by role | implemented |
