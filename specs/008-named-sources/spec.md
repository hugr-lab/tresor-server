# Spec 008: named material sources

- **Status**: accepted
- **Date**: 2026-10-05
- **Author**: hugr lab

## Summary

A reference's scheme names a **source**: `ref+<name>://…`. Today the name is the source's kind (`azkv`, `k8s`,
`vault`), so there is one source per kind. This spec lets the configuration add **named sources**: more
instances of a kind, each with its own connection, identity and allowlist, e.g. `ref+vault-us://…` beside
`ref+vault://…`, or `ref+partner://…` for a Key Vault in another tenant.

No protocol change: the reference syntax is the service's own (tresor's `protocol.md`).

## Problem

- **One Vault.** `ref+vault://` reads the Vault of the top-level `vault:` block. A second Vault (another
  region, another team's, an OpenBao beside a HashiCorp Vault) cannot be read.
- **One Azure identity.** `ref+azkv://` reads any vault in the allowlist, but as the service's one identity, in
  its one tenant and cloud. A Key Vault in a partner's tenant, or in a sovereign cloud beside the public one,
  cannot be read.
- **One allowlist and cache per kind.** Two sets of secrets cannot have different `cache_ttl`s.

## Design

### Configuration

```yaml
material:
  vault: {allow: [{mount: secret, prefixes: [duckdb/]}]}       # ref+vault://, as today (top-level vault:)
  sources:
    - name: vault-us                                            # ref+vault-us://<mount>/<path>#<field>
      kind: vault
      vault:                                                    # its own connection; the top-level one when unset
        address: https://bao.us.example:8200
        ca_file: /etc/tresor-ca/us.crt
        auth: {method: jwt, mount: jwt-eu-cluster, role: tresor, jwt_file: /var/run/tresor/vault-token/token}
      allow: [{mount: secret, prefixes: [duckdb/]}]
      cache_ttl: 0s
    - name: partner                                             # ref+partner://<vault>/<secret>[/<version>]
      kind: azkv
      azure: {identity: workload, client_id: <app id>, tenant_id: <the partner's tenant>}
      allow: [{vault: partner-kv, prefixes: [duckdb-]}]
      dns_suffix: .vault.azure.net
```

- **The name** is the scheme: `^[a-z][a-z0-9-]{0,15}$`. Unique among all sources. The built-in sections
  (`material.azkv`, `material.k8s`, `material.vault`) are sources named after their kind. A named source may
  not take a name a configured built-in section has. A future kind's built-in section (`aws`, `gcp`) that
  collides with a named source is a configuration error at start, not a silent change.
- **The kinds**: `vault` and `azkv`.
  - `k8s` is not one: another cluster would need a kubeconfig with credentials, a static secret.
  - Phase 4's kinds (AWS, GCP) take named instances from the start.
- **The connection** is the source's own: a `vault:` block (as the top-level one: address, namespace,
  ca_file, auth) or an `azure:` block (identity, client_id, and `tenant_id` for `workload`). Unset: the
  top-level one. The allowlist's syntax and rules are the kind's, unchanged.
- **No static secret**:
  - a second Vault logs in with `kubernetes`, `jwt` or `token_file`, as the first. The chart's `vaultToken`
    file serves both when both roles accept its audience;
  - a second Azure identity is a user-assigned managed identity (Container Apps holds several) or, under
    workload identity, another app registration with a federated credential to the same ServiceAccount,
    possibly in another tenant (`tenant_id`).

### The parse

- The scheme pattern grows from `[a-z0-9]{1,16}` to `[a-z][a-z0-9-]{0,15}`. Every reference written so far
  still parses.
- `material.Resolver` already keys sources by scheme. A source of a kind is constructed with its name
  (`Named`), and `Scheme()` returns that name; `Kind()` its kind. `Ref.Scheme` is the name, `Ref.Kind` the
  kind (a vault reference is written `#field` under any name).
- `config.Source(name)` resolves a source's connection: a named source's own blocks, or the top-level ones.
  The service builds its sources from `config.Sources()`, and the password's from `config.Source`.
- A reference's text after `://` is parsed by its kind, as today.

### The chart

- `vaultToken` serves named sources too: a named source's `vault:` with `kubernetes` or `jwt` and no
  `jwt_file` gets the chart's token file.
- The pod's own ServiceAccount token is mounted for a named source's `kubernetes` login with no token of its
  own, as for the top-level one.
- The render refuses a named source's `jwt` with no token, and `vaultToken` with no login to serve.

### `state.password_ref`

- It may name a named source: `ref+vault-us://…` reads with that source's connection.
- The rule is unchanged: outside that source's allowlist. The configuration check (`Material.admits`) learns
  the named sources.

### Audit, spans, metrics

- They name the source by its name (`ref+vault-us://…`, the scheme as written). The kind is added as an
  attribute (`tresor.source.kind`).

## Enforcement & security

- **Fail closed.**
  - A reference to a name no source has is refused at a write (`422 invalid_secret`), as today.
  - At a fetch it fails as a reference outside the allowlist does today: a secret's fetch `503`, a variable's
    read `500` (it will not resolve until the configuration changes).
- **Renaming or removing a source** strands the references that name it. They fail at fetch, never fall back
  to another source of the kind. The docs say so; listing the stranded references is a follow-up.
- **Allowlists are per source.** A path admitted by one source is not admitted by another of the same kind.
- **Admins write references** (spec 003's rule): a named source changes where, not who.
- **One connection per source.** A named source never reuses a token or a credential of another, except the
  top-level one when it inherits it explicitly (no block).

## Testing

- Config: names (pattern, uniqueness, built-in collisions), kinds (`k8s` refused), the inheritance of the
  top-level blocks, `tenant_id` only with `workload`.
- Material: two vault sources against the two CI servers (OpenBao and Vault) at once, each with its own
  allowlist; a reference admitted by one refused by the other; a removed source's references failing at fetch.
- `password_ref` through a named vault source.
- The conformance suite unchanged; kind: a second OpenBao, `ref+bao2://`, read through the protocol.
- Azure: a named `azkv` source is tested with a fake credential; the live run (another tenant) is a manual
  check, not CI.

## Alternatives considered

- **A Vault address in the reference** (`ref+vault://bao.us.example/...`): the allowlist would have to name
  hosts, and a writer could point the service at any host it can reach with its token. Rejected: an admin
  names sources in configuration, a writer only picks one.
- **Prefixing the name inside the path** (`ref+vault://us/secret/...`): ambiguous with mounts. Rejected.

## Follow-ups

- `tresor-server refs`: list the stored references whose source is not configured (after a rename).
- Phase 4 (AWS, GCP) kinds, named from the start.
