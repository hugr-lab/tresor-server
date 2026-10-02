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
the reference. Three sources: Azure Key Vault (`ref+azkv://`), Kubernetes Secrets (`ref+k8s://`), and OpenBao or
HashiCorp Vault KV v2 (`ref+vault://`).

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

- **The allowlist**: only the mounts listed, and only the paths that start with a listed prefix (none listed:
  all). The service's Vault policy gives `read` on `<mount>/data/<prefix>*`.
- **Each read** fetches the secret's current version and logs that version, never the value. A new version
  in Vault reaches DuckDB at its next fetch.
- **The field must be text**. A deleted secret, a missing field or one that is not a string fails the fetch.
- **The parse is strict**:
  - a one-segment mount;
  - path segments of letters, digits, `_`, `.` and `-`, with no `.` or `..`;
  - no escape, no query, one `#field`.
- **`state.password_ref: ref+vault://…`** reads a database's password. As for every source, it must be
  outside `material.vault.allow`.

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
