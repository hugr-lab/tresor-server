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
const tresor = await import('https://secrets.corp.example/ui/mfe/tresor.js')
tresor.contract                          // 1: the contract below
const mounted = tresor.mountTresor(element, {
  apiBase: 'https://secrets.corp.example',
  getToken: async (audience, { renew } = {}) => token, // an access token with the service's audience, before each request
  audience: 'duckdb-secrets',            // optional: handed to getToken when the shell's tokens lack it
  basePath: '/platform/secrets',         // the shell's path the console lives under
  theme: 'dark',
  locale: 'en',                          // the only one now; another falls back to 'en'
  onNavigate: (path, { replace }) => history[replace ? 'replaceState' : 'pushState'](null, '', path),
  onTitle: (title) => setBreadcrumb(title),
  onUnauthorized: () => signInAgain(),   // the service refused the token, renewed too
})
mounted.update({ theme: 'light' })         // or { path } when the shell navigates, { locale }
mounted.unmount()
```

Or the element: `<tresor-console api-base="…" base-path="…" audience="…" theme="dark" locale="en">`, mounted once its
`getToken` property is set (a token is never an attribute); its `data-contract` names the contract; the shell's
callbacks are properties, or the events `tresor-navigate`, `tresor-title` and `tresor-unauthorized`.

### The contract, version 1

- **The version**: `contract` (and `data-contract` on the element) is `1`. An addition (an option, an event) keeps
  it; a change that breaks a shell makes it `2`, announced in the release notes.
- **Whether to show the entry**: `GET <apiBase>/v1/whoami` with the user's token; `permissions.create` is `true`
  for an administrator. Hide the entry otherwise; mounted anyway, the console says it is for administrators.
- **The token**: `getToken` is called before each request, so it should answer from the shell's library's cache
  (which renews it). When the service answers 401, the console calls `getToken(audience, { renew: true })` once
  and retries (requests refused together share one renewal); refused again, it calls `onUnauthorized` (at most
  once every 30 seconds per element) and shows "Your session ended", with "Try again", until a request succeeds. The shell signs the user in again - by a popup, so an edit in progress stays.
  The console sends nothing on its own while the user is idle.
- **The theme**: `theme` picks the light or dark defaults; the shell overrides any of them by setting the
  variables on the element - they win over the console's own in either theme:

  ```css
  .tresor-slot { --brand: #3a7bd5; --brand-strong: #2c5fa8; --surface: #fff; --ink: #111; }
  ```

  The variables: `--surface`, `--surface-soft`, `--ink`, `--ink-muted`, `--border`, `--brand`, `--brand-strong`,
  `--on-brand`, `--focus`, `--success`, `--success-soft`, `--warning`, `--warning-soft`, `--danger`,
  `--danger-soft`, `--row`. The console sets `data-tresor-theme` on the element while mounted.
- **The layout**: the content needs 960 px; narrower, it scrolls inside the element. The shell gives it its height.
- **Caching**: `tresor.js` has a fixed name, `Cache-Control: no-cache` and an `ETag`: each load revalidates (a 304)
  and an upgrade is picked up at once; its chunks have hashed names and are cached for good.

### A token for the console

People sign in to the platform, whose tokens carry the platform's audience; the service accepts its own
(`duckdb-secrets`). The shell gets a second token from the same session, with no second sign-in:

- **Entra ID**: MSAL's `acquireTokenSilent({ scopes: ['api://duckdb-secrets/.default'] })`. The platform's app
  registration has a delegated permission on the duckdb-secrets API, admin-consented; the administrators' app
  role is assigned on the duckdb-secrets app and comes in that token's `roles`. MSAL renews it by its refresh
  token; `renew: true` maps to `forceRefresh: true`.
- **ZITADEL**: the platform's sign-in also asks for the scope `urn:zitadel:iam:org:project:id:<tresor's
  project>:aud`; one token then carries both audiences.

```yaml
ui:
  allowed_origins: ['https://platform.corp.example']   # CORS on /ui/mfe/, /v1 and /admin/v1, for them only
```

- The console draws in the element's shadow root, with its own styles: the shell's CSS does not reach it, and
  it needs no `'unsafe-inline'`. The shell's CSP allows the service's origin in `script-src`, `font-src` and
  `connect-src`.
- No cookie is sent or honoured: the token is the only credential.
- A shell that proxies the service under its own origin (recommended) needs no `allowed_origins`.

## Turning it off

`ui.enabled: false` removes `/ui/` and `/admin/v1`; the protocol is unchanged.
