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
- **No password of the service's own** on Azure: a managed identity for Key Vault and the database.
- **Transport**: HTTPS (or TLS at the ingress, `tls.offload`); to PostgreSQL `sslmode=verify-full`, to SQL
  Server `encrypt=true`, with the certificate checked, off the local machine.

## What it trusts

- **The identity providers** it is configured with, and their signing keys.
- **Whoever can write its database.** The sealed values are bound to their rows, but a secret's grants, a
  delegation grant's user and expiries are not sealed: write access to the database can change who may use
  what. Protect it as the service itself. On the Kubernetes store these are authenticated by a MAC: a
  change by hand is refused, but a whole older resource put back (a rollback) is not - only the service's
  account should write its resources.
- **Whoever holds the KEK**, with the database, holds the material.
- **Administrators**: they write secrets and references. The allowlist bounds what a reference can read.

## Static secrets that remain

- A **local KEK** and a **database password**: for development and small installs.
- The **client secret** of the service's own client at the IdP, when it mints tokens for callers
  (`token_exchange`).
