---
title: An issuer or a material source
---

# An issuer or a material source

**When**: an identity provider or a place references read from (a Key Vault, a Vault server, a namespace, a
Secrets Manager account, a GCP project) is added, renamed or removed; an allowlist changes.

**Who**: the platform operator, with the secrets administrators whose references it touches.

Every change here is a [configuration change](configuration.md): `refs` before it, readiness after it.

## An issuer

- **Added**: `issuers` gains an entry ([tresor's reference](https://hugr-lab.github.io/tresor/reference-server/)).
  Readiness gains `issuer <url>` and, with `exchange`, `exchange <url>`. A principal from it is new: grant to it
  as to any role.
- **Removed**: its tokens are refused. What was granted to its principals stays stored, and serves no one: an
  administrator revokes it.
- **Its URL changed** (a new tenant, a new realm): a principal is named by its issuer
  (`subject:<issuer>|<sub>`); grants made to the old principals do not match the new ones. Roles and groups are
  matched by name (`role:…`, `group:…`): grants to those carry over when the new issuer gives the same names.
- The console's sign-in uses the issuers with a `client_id`: register `<public_url>/ui/callback` at a new one
  ([Console](../console.md#signing-in)).

## A material source

The sources: each kind's section (`material.azkv`, `material.k8s`, `material.vault`, `material.aws`,
`material.gcp`) and the named ones (`material.sources`, spec 008). See
[References](../references.md#named-sources).

- **Added**: no reference uses it yet. Give the service's identity the read on the new place (*Key Vault Secrets
  User*, `get` on Secrets - the chart makes the Role -, the Vault policy, `secretsmanager:GetSecretValue`,
  `roles/secretmanager.secretAccessor`), then let administrators write references to it.
- **Renamed or removed**: its references are stranded. They are refused at a write, and fail at a fetch
  (`503`). They are never read by another source of the kind.
- **An allowlist narrowed** (a vault, a namespace, a prefix out): the references outside it fail the same way.
- **`state.password_ref`** must stay outside every allowlist: a widened allowlist that reaches it stops the start.
- **The service's own namespace** is never in `material.k8s.allow`: the start stops.

## Steps

1. **Find the references**: `refs` with the new configuration ([Changing the configuration](configuration.md)).
   Each finding names the secret or variable, the parameter and the reason.
2. **Rewrite them** first, for a rename or a move: an administrator replaces each secret or variable with the new
   reference (DuckDB, or the console). For a rename, keep the old source until then - two sources may reach the
   same place, each with its own allowlist.
3. **Deploy** the new configuration.
4. **Remove** the old source, or the allowlist entry, in a change of its own, with `refs` before it.

## Check

- `refs -resolve` exits `0` (`<fullname>-refs`, `<prefix>-refs`).
- The console's References check; its Service screen lists the sources and where each may read.
- `tresor.references` by scheme and outcome ([Observability](../observability.md#metrics)): no `error` for the
  source.

## Back

Deploy the old configuration ([Changing the configuration](configuration.md#back)). The references are stored as
written: with the old source back, they resolve again.
