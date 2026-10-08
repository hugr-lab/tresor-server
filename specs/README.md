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
| [001](001-architecture/spec.md) | tresor-server - state stores, KEK, material by reference, deployment, phases | accepted |
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
| [012](012-aws-gcp/spec.md) | phase 4 - AWS and GCP: KMS as the KEK, Secrets Manager and Secret Manager as sources, no static secret | accepted |
| [013](013-entra-on-behalf-of/spec.md) | Entra On-Behalf-Of for `token_exchange` secrets: `exchange.grant: on_behalf_of` | implemented |
