---
title: Using the console
---

# Using the console

A walk through the console at `<public_url>/ui/`, on the [Docker demo](docker.md) with an OpenBao beside
it for references. What the console is and how to configure it: [Console](console.md).

## Signing in

![The sign-in page: one button per identity provider with a public client](/img/console/01-sign-in.png)

**Sign in with …** opens the identity provider's login (Authorization Code with PKCE). The console keeps the
token in memory only; a reload in the same tab signs in again without a click.

The console is for **administrators** (`policy.admins`). Anyone else is told so and sees nothing - what their roles
are granted reaches them in DuckDB:

![A person with no administrator role: the console is for administrators](/img/console/12-not-an-administrator.png)

## Secrets

![The secrets list: name, type, scope, comment, version and your verbs](/img/console/02-secrets.png)

- **Search** by name, type, comment or scope; **Dynamic** shows the secrets made per caller
  ([generated parameters](generated.md)); **Granted to me** the ones your own roles may use - an administrator holds
  no `use` by being one.
- The **⋯** menu of a row opens, replaces or deletes it. A delete asks for the secret's name.

### A secret's parameters

![A secret: its parameters - values hidden, a reference shown with its source - and who may use it](/img/console/03-secret.png)

- A **secret value** (in `redact_keys`) is never shown, here or anywhere: it is kept or set anew.
- Other values are hidden until **Show values** - and each such read is in the audit.
- A **reference** (`ref+vault://…`, `ref+azkv://…`) is shown as written, with its source; the value stays in the
  vault and is read at each fetch.
- **SQL** shows the statement the secret amounts to, secret values masked.

### Creating a secret

![The editor: a type's template, a reference to OpenBao, and the statement it amounts to](/img/console/04-new-secret.png)

- **Type** is searched over DuckDB's extensions' secret types; the type's template fills its parameters, the
  sensitive ones marked **secret**.
- A parameter's value is typed, or a **Reference**: pick the source, its parts, and the console shows where the
  source may read (`material.*.allow`) - a reference outside it is refused.
- The **scope** is what DuckDB matches the secret by (`s3://lake/raw`).
- **What this amounts to** is the `CREATE PERSISTENT SECRET` statement, live.

**Replace** later keeps what you leave untouched - a secret value too - and saves a new version; if someone saved
meanwhile, the console says so and carries your edit onto theirs.

## Who may use it

![Grants: a group and a role being granted use](/img/console/05-grant.png)

A grant gives `use` to a role (`role:<name>`) or a group (`group:<name>`) of the identity provider - never to a
person. **Grant** writes it at once; **×** revokes it, and the next query in a DuckDB of that role no longer finds the
secret.

### Access: by role or group

![Access: what role:analysts may use, granted and revoked in one place](/img/console/06-access.png)

**Access** turns it around: pick a role or a group and see every secret and variable it may use, grant it another
one, or revoke. The page's address (`?principal=role:analysts`) can be shared.

## References check

![References check: every reference checked against the sources, and read; one finding](/img/console/07-references-check.png)

Every `ref+…` in secrets and variables, checked against the sources as configured now - **Check** - or also read
from the vault - **Check and read each**. Run it before a configuration change: a renamed source or a narrowed
allowlist strands references. Here a reference points to a path that is not in OpenBao.

## Variables

![Variables: a plain one, and one made per caller from their token](/img/console/08-variables.png)

Named strings DuckDB reads with `getvariable('name')`: buckets, endpoints, settings - granted like secrets. A value
can be plain, a reference, or made per caller (`mint+claim://preferred_username`: [Variables](variables.md)).

## Service

![The service: readiness, the key, the identity providers, the policy and the reference sources](/img/console/09-service.png)

What the service runs with, read-only: each readiness check; the KEK's kind and current version, the data keys and
their age ([Data keys](administration/data-keys.md)); the identity providers; the capabilities, the administrators
and the actors; the reference sources and where each may read.

## Signing out

![The account menu: who is signed in, the session's end, revoke sessions, sign out](/img/console/10-account.png)

The account menu shows who is signed in (the name, the issuer, the roles) and when the session ends.

- **Revoke my sessions on servers** ends every session a server holds for you
  ([delegation](https://hugr-lab.com/docs/tresor/protocol/#delegation)).
- **Sign out** ends the session at the identity provider too.

When the session ends while you edit, the console says so and signs you in again in a popup - the edit is kept.
