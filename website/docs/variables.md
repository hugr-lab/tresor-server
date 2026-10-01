---
title: Variables
---

# Variables

A **variable** is a named string the service holds for its callers: a bucket, an endpoint, a dataset's path,
a setting shared by a team. tresor reads one with `corp.variable('name')`. Variables are an optional part of
the protocol (tresor spec 018); this service supports them on every store, and says so in its discovery
(`capabilities.variables`).

```sql
CALL corp.set_variable('lake_bucket', 's3://sales-lake', comment := 'the sales team''s lake');
SELECT * FROM corp.grant_variable('lake_bucket', 'role:analysts', ['use']);
SELECT corp.variable('lake_bucket');
```

## The rules

- **They are the secrets' rules**: names, permissions, conditional writes, delegation, errors.
  - Administrators create and manage.
  - Roles get `use` through grants.
  - An invisible variable is `404`; one seen without `use` is `403`.
- **The value is a UTF-8 string**, up to 64 KiB.
- **Sealed at rest**, as a secret's params are. Any value may be material, a connection string with a
  password say.
- **A list carries no value.** Only a read with `use` returns it.

## References

A value may name where its content lives, with the [references](references.md)' syntax and rules:

```sql
CALL corp.set_variable('warehouse_dsn', 'ref+azkv://corp-vault/duckdb-warehouse-dsn');
```

- Written by an administrator only, within the allowlist (`422` outside it).
- A value that looks like a reference is one: `ref+…` (in any case, after spaces) must be a valid reference
  within the allowlist, or the write is refused (`422`). Such a text cannot be kept as a plain value.
- Read at each fetch, with the service's identity. A rotation reaches the next read.
- **`sensitive: true`**: the resolved value is material. tresor keeps it out of logs and its audit, and caches
  it per caller.
- A reference that does not resolve fails the read:
  - `503 service_unavailable` when it may resolve later (the vault down, the secret missing);
  - `500 service_error` when it will not (outside the allowlist now).

## Where they are kept

| Store | Where |
| --- | --- |
| memory | beside the secrets |
| SQLite, PostgreSQL, SQL Server | the tables `variables` and `variable_grants` |
| Kubernetes | `TresorVariable` resources, with a MAC as a `TresorSecret` has |
