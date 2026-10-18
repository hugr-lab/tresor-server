---
title: Supported versions
---

# Supported versions

**Releases**: the latest minor gets fixes (0.4.x); before 1.0 nothing is backported, and an upgrade may ask for a
step of its own ([Upgrading](administration/upgrading.md)). Security reports:
[SECURITY.md](https://github.com/hugr-lab/tresor-server/blob/main/SECURITY.md).

What follows is what is **checked** - on every pull request, or by hand on a cloud before a release. Another
version of the same product is expected to work; it has not been run.

## Every pull request (CI)

| Part | Checked with |
| --- | --- |
| The protocol | tresor's conformance suite, tresor at `fc97659` (its main, spec 037; DuckDB `f8f3f4d`, the v2.0 branch), on every state store, with its `generators.test` |
| SQLite | `modernc.org/sqlite` (built in), one replica |
| PostgreSQL | 17, two replicas behind a round-robin proxy |
| SQL Server | 2022, two replicas |
| The Kubernetes store | kube-apiserver and etcd 1.37.0 (envtest), two replicas |
| The chart | kind v0.31.0 (Kubernetes 1.35.0): the Kubernetes store with its admission policy, PostgreSQL in the cluster, OpenBao, Keycloak; its manifests checked against the 1.30.0 schemas (kubeconform) |
| Identity providers | Keycloak 26.6 in kind (federated client authentication), 26.4 for the console's end to end; ZITADEL v4.19 (token exchange, `key_file`) |
| OpenBao, Vault | OpenBao 2.4.1 and Vault 2.1.1 (the Go tests); OpenBao in kind: Kubernetes login, the KEK in Transit, references |
| AWS | KMS and Secrets Manager through moto (emulated) |
| Recipes | Bicep built; Terraform (Cloud Run, ECS) formatted and validated |
| The console | its unit tests; end to end in a browser against the service |

## On the clouds (by hand)

Run live with the scripts in `scripts/dev/`, on the provider's default Kubernetes version of the day. These ran
0.1-0.3 images, before the MAC's default and `cors`; what 0.4 changed is covered by CI above.

| Platform | What ran | When |
| --- | --- | --- |
| Azure Container Apps | the recipe; Key Vault KEK and references; Azure SQL and Azure Database for PostgreSQL 16 by Entra | 0.1-0.3 (2026-09-30, 2026-10-08, 2026-10-14) |
| AKS | the chart, workload identity, Key Vault | 2026-10-01 |
| Entra ID | On-Behalf-Of (`token_exchange`), service logins (managed identity, federated credential) | 2026-10-08, 2026-10-14 |
| GKE Autopilot | the chart, Workload Identity, Cloud KMS, Secret Manager, Cloud SQL PostgreSQL 16 by IAM | 2026-10-14 |
| Cloud Run | the recipe: Cloud SQL over Private Service Connect, the jobs | 2026-10-14 |
| EKS | the chart (the Kubernetes store), IRSA, KMS (an encrypt key and an HMAC key), Secrets Manager, the maintenance jobs | 2026-10-14 |
| ECS Fargate | the recipe: ALB, RDS PostgreSQL 16 by IAM, the commands' task | 2026-10-14 |

## The artifacts

- **The image**: `ghcr.io/hugr-lab/tresor-server`, linux/amd64 and linux/arm64, distroless, non-root.
- **The chart**: `oci://ghcr.io/hugr-lab/charts/tresor-server`; CI lints and installs it with the latest Helm (4.x).
- Both signed from 0.4, the image with an SBOM and provenance: [Verifying the artifacts](security.md#verifying-the-artifacts).
