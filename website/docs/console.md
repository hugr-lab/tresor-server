---
title: Console
---

# Console

The service serves a management console at `<public_url>/ui/`: a web page for **administrators** (the
configuration's `policy.admins`). Day to day, secrets are managed from DuckDB (`CREATE PERSISTENT SECRET … IN
corp`); the console is for looking at what the service holds and changing it without a DuckDB at hand.

- **Secrets**: the list (search, filters, type), a secret's parameters, its grants and the statement it
  amounts to; create from a type's template (DuckDB's core extensions, DuckLake, SQL Server), replace keeping
  the stored values, delete.
- **Variables**: the same for [variables](variables.md).
- **Access**: what each role and group may use, granted and revoked in one place.
- **References check**: every `ref+…` checked against the [sources](references.md) as configured now, the
  check `tresor-server refs` runs, optionally reading each one.
- **Service**: the version, the state store, the KEK's kind and current version, the issuers, the sources and
  where they may read, the policy, readiness.

## What an administrator sees

- A parameter in the secret's `redact_keys` (DuckDB marks a type's sensitive parameters; the console's
  "secret" switch does too) is **never shown**: it is kept or set anew.
- A parameter not marked is shown on request (**Show values**), and each such request is audited as `reveal`.
- A reference is shown as written, never what it resolves to.
- Views through the console's own API (`/admin/v1`) are audited as `inspect`, and Show values as `reveal`,
  subject to `audit.level` (see [Observability](observability.md)); the lists and grants come from the protocol's
  routes, audited as theirs. Using a secret still needs a grant: an administrator holds no `use` by being one.

## Signing in

The console signs people in with the issuers that have a `client_id`: a **public client** (no secret),
Authorization Code with PKCE.

```yaml
issuers:
  - issuer: https://idp.corp.example/realms/corp
    audience: duckdb-secrets
    client_id: tresor-console
    scopes: [openid]
policy: {admins: ['role:secrets_admin']}
ui:
  environment: prod            # optional: a badge in the top bar
```

At the IdP:

- **Redirect URI**: `<public_url>/ui/callback` (the sign-in popup uses it too); **post-logout redirect URI**:
  `<public_url>/ui/`.
- **Web origin** (CORS for the token endpoint): the service's origin.
- **The audience**: the access token must carry the service's `audience`. Keycloak: an audience mapper on the
  client. ZITADEL: the project's audience. Entra: the API's scope in `scopes`
  (`api://…/.default`).
- **Roles** in the token, as for DuckDB's callers (`roles_claim`).

The access token stays in the page's memory; it is renewed with the refresh token. When the session ends, the
page says so and signs in again in a popup: an edit in progress is kept.

The page runs under a strict Content-Security-Policy (its own scripts, styles and fonts only; the issuers'
origins for the sign-in). An IdP whose token or user-info endpoint is on another host is added with
`ui.connect_src`. The page is not framed, except by `ui.frame_ancestors`.

## As a microfrontend

A platform's shell can mount the console in its own pages: the shell signs in, navigates and sets the theme.

```js
const { mountTresor } = await import('https://secrets.corp.example/ui/mfe/tresor.js')
const tresor = mountTresor(element, {
  apiBase: 'https://secrets.corp.example',
  getToken: async (audience) => token,   // an access token with the service's audience, before each request
  audience: 'duckdb-secrets',            // optional: handed to getToken when the shell's tokens lack it
  basePath: '/platform/secrets',         // the shell's path the console lives under
  theme: 'dark',
  onNavigate: (path, { replace }) => history[replace ? 'replaceState' : 'pushState'](null, '', path),
  onTitle: (title) => setBreadcrumb(title),
})
tresor.update({ theme: 'light' })          // or { path } when the shell navigates
tresor.unmount()
```

Or the element: `<tresor-console api-base="…" base-path="…" audience="…" theme="dark">`, mounted once its `getToken`
property is set (a token is never an attribute).

```yaml
ui:
  allowed_origins: ['https://platform.corp.example']   # CORS on /ui/mfe/, /v1 and /admin/v1, for them only
```

- The console draws in the element's shadow root, with its own styles: the shell's CSS does not reach it, and
  it needs no `'unsafe-inline'`. The shell's CSP allows the service's origin in `script-src`, `font-src` and
  `connect-src`.
- No cookie is sent or honoured: the token is the only credential.
- A shell that proxies the service under its own origin needs no `allowed_origins`.

## Turning it off

`ui.enabled: false` removes `/ui/` and `/admin/v1`; the protocol is unchanged.
