---
title: References
---

# References: material that stays where it is

An organization often keeps a credential in Azure Key Vault already - a storage account key that Azure
rotates, a token another team renews. A secret's parameter can name it instead of copying it:

```sql
CREATE PERSISTENT SECRET lake IN corp (
    TYPE s3,
    KEY_ID 'AKIA...',
    SECRET 'ref+azkv://corp-vault/lake-s3-secret',
    SCOPE 's3://lake'
);
```

The service reads the value at each fetch, with its own identity. DuckDB gets the value; the store keeps only
the reference. Four kinds of source: Azure Key Vault (`ref+azkv://`), Kubernetes Secrets (`ref+k8s://`),
OpenBao or HashiCorp Vault KV v2 (`ref+vault://`), and AWS Secrets Manager (`ref+aws://`, see [AWS](aws.md#references-secrets-manager)). [Named sources](#named-sources) add more of a kind under
names of their own (`ref+vault-us://`).

## Key Vault: the syntax

`ref+azkv://<vault>/<secret>[/<version>]`, as a parameter's whole VARCHAR value.

- `<vault>` is the vault's name: `https://<vault>.vault.azure.net`.
- `<secret>` is the Key Vault secret's name; `<version>` pins one version (32 hex digits).
- With no version, the current one is read at each fetch: a rotation in the vault reaches DuckDB at its
  next fetch.
- The parser is strict: no escapes, no other path segment, no query. The URL to the vault is built from the
  parsed parts, never from the text.

## Key Vault: the allowlist

```yaml
material:
  azkv:
    allow:
      - vault: corp-vault
        prefixes: [lake-, duckdb-]
azure: {identity: managed}
```

- Only the vaults listed, and only the secrets whose names start with a listed prefix (none listed: all),
  are read. Otherwise an administrator could make the service read any secret its identity can reach.
- Vault and secret names are compared without case, as Key Vault has them.
- The service's identity needs *Key Vault Secrets User* on each vault, or on the secrets it may read.

## Kubernetes Secrets

`ref+k8s://<namespace>/<secret>/<key>`: one key of a Secret.

```yaml
material:
  k8s:
    allow:
      - namespace: data-team
        prefixes: [duckdb-]
```

- Only the namespaces listed, and only the Secrets whose names start with a listed prefix (none listed: all).
  Names are compared exactly, as Kubernetes has them. A prefix is a plain start: `duckdb` also matches
  `duckdbx-…` - end it with a dash.
- **Never the service's own namespace**: its own credentials are there (a local KEK, a password, a client
  secret). The service does not start if the allowlist names it.
- The service reads with its ServiceAccount: it needs `get` on Secrets in each namespace listed (the chart
  makes a Role per namespace). A Role cannot match name prefixes: the prefixes are the allowlist's alone.
- The value must be UTF-8 text: a reference is a VARCHAR value.
- The resolution is logged with the Secret's observed `resourceVersion`, never the value.
- A Secret synced from a vault by another tool (External Secrets, the CSI driver) is served the same way: a
  rotation reaches DuckDB at its next fetch.

## OpenBao and HashiCorp Vault: KV v2

`ref+vault://<mount>/<path>#<field>`: one field of a KV v2 secret.

```yaml
material:
  vault:
    allow:
      - mount: secret
        prefixes: [duckdb/]
    cache_ttl: 0s
vault: {address: https://bao.example.eu:8200, auth: {method: kubernetes, role: tresor-server}}
```

- **The mount is KV version 2**. A mount of another kind is refused at the read.
- **The allowlist**: only the mounts listed, and only the paths that start with a listed prefix (none listed:
  all). A prefix is a plain start: end it with `/` (`duckdb/`), as the service's Vault policy does with
  `read` on `<mount>/data/<prefix>*`.
- **Each read** fetches the secret's current version (or, with `cache_ttl`, one read within it) and logs that
  version, never the value. A new version in Vault reaches DuckDB at its next fetch.
- **The field must be text**. A deleted secret, a missing field or one that is not a string fails the fetch.
- **The parse is strict**:
  - a one-segment mount;
  - path segments of letters, digits, `_`, `.` and `-`, with no `.` or `..`;
  - no escape, no query, one `#field`.
- **`state.password_ref: ref+vault://…`** reads a database's password. As for every source, it must be
  outside `material.vault.allow`. A named source's reference (`ref+vault-us://…`) reads with that source's
  connection. It must be outside the allowlist of **every** source of its kind: two sources may reach the same
  server.

## Named sources

The name after `ref+` is a **source**. Each kind's section (`material.azkv`, `material.k8s`, `material.vault`)
is a source named after its kind. `material.sources` adds more, each with its own name, connection and
allowlist (spec 008):

```yaml
material:
  vault: {allow: [{mount: secret, prefixes: [duckdb/]}]}       # ref+vault://, with the top-level vault:
  sources:
    - name: vault-us                                            # ref+vault-us://<mount>/<path>#<field>
      kind: vault
      vault:                                                    # its own; the top-level vault: when unset
        address: https://bao.us.example:8200
        auth: {method: jwt, mount: jwt-eu-cluster, role: tresor, jwt_file: /var/run/tresor/vault-token/token}
      allow: [{mount: secret, prefixes: [duckdb/]}]
    - name: partner                                             # ref+partner://<vault>/<secret>[/<version>]
      kind: azkv
      azure: {identity: workload, client_id: <app id>, tenant_id: <the partner's tenant>}
      allow: [{vault: partner-kv, prefixes: [duckdb-]}]
```

- **The name** is the references' scheme: a lower-case letter, then letters and digits with single dashes
  between, 16 at most.
  - The kinds' names are reserved: `azkv`, `k8s`, `vault`, `aws`, `gcp`. So every reference written before
    keeps its meaning.
- **The kinds**: `vault` and `azkv`. `k8s` reads this cluster only: another would need a kubeconfig's
  credentials.
- **The connection**:
  - a `vault:` block, as the top-level one, or the top-level one when unset;
  - an `azure:` block: `identity`, `client_id` (required, but for `default`), and `tenant_id` (with
    `workload`: an app registration in another tenant, federated to the same ServiceAccount). The top-level
    `azure:` when unset.
  - Neither needs a static secret. A second Azure identity is another user-assigned managed identity
    (Container Apps), or another app registration under workload identity.
- **Each allowlist is the source's own.** A place one source admits is not admitted for another of the kind.
  Its syntax is the kind's: `{mount, prefixes}` for `vault`, `{vault, prefixes}` for `azkv`. `cache_ttl` and,
  for `azkv`, `dns_suffix` are the source's too.
- **Renaming or removing a source strands its references.** They are refused at a write, and fail at a fetch
  as a reference outside the allowlist does. They are never read by another source of the kind. Rename a
  source only with its references rewritten: `tresor-server refs` lists them (see
  [Operations](operations.md#checking-references)).
- The audit and the logs name a reference as written (`ref+vault-us://…`). Spans add the kind
  (`tresor.source.kind`).

## The rules

At a write (`PUT`), every parameter that starts with `ref+`:

- must name a configured source, parse, and be within the allowlist - otherwise `422 invalid_secret`. It is
  never stored as a literal;
- must be a VARCHAR value, in a secret not minted per caller (`token_exchange`);
- is added to `redact_keys`: the resolved value never shows in `duckdb_secrets()`.

A near miss (`REF+...`, a space before `ref+`) is refused too, rather than kept as text. Only administrators
write secrets, so only they write references.

At a fetch with `use`:

- each reference is read now, and the allowlist is checked again - the configuration may have changed;
- any failure (not found, denied, disabled, outside the allowlist, unreachable) fails the fetch:
  `503 service_unavailable`. Never an empty or a stale value;
- each resolution is logged: the secret, the reference, the version. Never the value.

`material.azkv.cache_ttl` (at most 5 minutes) keeps a value read for that long, for the vault's request
limits. It is the longest a value may be read stale.

## The database's password

`state.password_ref` (PostgreSQL, SQL Server, `auth: password`) reads the password the same way, for each
new connection:

```yaml
state:
  kind: postgres
  dsn: host=pg.db.svc user=tresor dbname=tresor sslmode=verify-full
  auth: password
  password_ref: ref+k8s://db/tresor-pg/password
```

- It must be outside every `material` allowlist: otherwise an administrator could write a secret that names
  it, and read the database's password. The service does not start if it is not, nor if it does not parse.
- The allowlist compares where a reference points, not the credential: a copy of the password synced into an
  allowlisted namespace or vault (External Secrets, say) is readable there.
- The service needs `get` on that one Secret (the chart grants it by name), or *Key Vault Secrets User* on
  that one secret.
