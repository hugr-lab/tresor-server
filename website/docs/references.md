---
title: References
---

# References: material that stays in Key Vault

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

The service reads the value in Key Vault at each fetch, with its own identity. DuckDB gets the value; the
store keeps only the reference.

## The syntax

`ref+azkv://<vault>/<secret>[/<version>]`, as a parameter's whole VARCHAR value.

- `<vault>` is the vault's name: `https://<vault>.vault.azure.net`.
- `<secret>` is the Key Vault secret's name; `<version>` pins one version (32 hex digits).
- With no version, the current one is read at each fetch: a rotation in the vault reaches DuckDB at its
  next fetch.
- The parser is strict: no escapes, no other path segment, no query. The URL to the vault is built from the
  parsed parts, never from the text.

## The allowlist

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
