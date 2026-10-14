---
title: Security
---

# Security

tresor's [security model](https://hugr-lab.github.io/tresor/security/) covers the protocol and the
extension: tokens, the permission model (administrators manage, roles use), servers acting for users. This
page covers what the service adds.

## What it guarantees

- **Fail closed.** A KEK that does not unwrap, a sealed value that does not open, a reference that does not
  resolve, a store that does not answer: an error for that request, never an empty or a stale value.
- **Nothing sensitive leaves the service** but material, to a caller allowed to `use` it. No material, token,
  data key, grant id or configuration value in a log, an error or the readiness answer.
- **Material is sealed at rest**: AES-256-GCM under data keys the KEK wraps, bound to its secret and
  version. A delegation grant's tokens are sealed too, and its id is stored only as a hash.
- **References are an administrator's**, within the allowlist, checked at the write and again at each
  resolution.
- **Every write is compare-and-set**, so several replicas never lose or cross a write.
- **No password of the service's own** on Azure: a managed identity (Container Apps) or workload identity
  (AKS) for Key Vault and the database.
- **Transport**: HTTPS (or TLS at the ingress, `tls.offload`); to PostgreSQL `sslmode=verify-full`, to SQL
  Server `encrypt=true`, with the certificate checked, off the local machine.

## What it trusts

- **The identity providers** it is configured with, and their signing keys.
- **Whoever can write its database.** The sealed values are bound to their rows, but a secret's grants, a
  delegation grant's user and expiries are not sealed: write access to the database can change who may use
  what. Protect it as the service itself. These rows carry a MAC, checked on every store by default (on the SQL
  stores since 0.4, [`state.mac`](state.md#the-sql-stores-mac-statemac)): a change by hand is refused, but a
  deleted row, or a whole older row put back (a rollback), is not - only the service's account should write
  them.
- **Whoever holds the KEK**, with the database, holds the material.
- **Administrators**: they write secrets and references. The allowlist bounds what a reference can read.

## Verifying the artifacts

From 0.4 the image and the chart are signed keylessly (cosign, spec 022): by the workflow that built them, with
its GitHub OIDC identity - no key exists to steal. Check the identity, with cosign v3 or later:

```sh
cosign verify ghcr.io/hugr-lab/tresor-server:v0.4.0 \
  --certificate-identity-regexp '^https://github.com/hugr-lab/tresor-server/\.github/workflows/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

cosign verify ghcr.io/hugr-lab/charts/tresor-server:0.4.0 \
  --certificate-identity-regexp '^https://github.com/hugr-lab/tresor-server/\.github/workflows/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

- **Verify a digest, deploy that digest**: a tag can move; `image.tag: v0.4.0@sha256:…` on the chart (the same
  reference in a recipe's image) pins what was verified. A policy controller (Kyverno, Sigstore's policy-controller) can require the
  signature at admission.
- **The SBOM and the provenance** (BuildKit's attestations, beside the image in the registry):

  ```sh
  docker buildx imagetools inspect ghcr.io/hugr-lab/tresor-server:v0.4.0 --format '{{ json .SBOM }}'
  docker buildx imagetools inspect ghcr.io/hugr-lab/tresor-server:v0.4.0 --format '{{ json .Provenance }}'
  ```

- **The scan**: every image is scanned (Trivy) before it is pushed; a HIGH or CRITICAL finding with a fix stops
  the release. `:edge` (main) is signed the same way.

Report a vulnerability as [SECURITY.md](https://github.com/hugr-lab/tresor-server/blob/main/SECURITY.md) says.

## Static secrets that remain

- A **local KEK** and a **database password**: for development and small installs.
- The **client secret** of the service's own client at the IdP, when it mints tokens for callers
  (`token_exchange`).
