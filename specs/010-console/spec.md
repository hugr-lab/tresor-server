# Spec 010: the management console

- **Status**: accepted
- **Date**: 2026-10-05
- **Author**: hugr lab

## Summary

A web console for administrators: browse, create, replace, delete and grant secrets and variables, check
references, see the service. It is served by tresor-server itself at `/ui/`, logs in with the same OIDC
issuers, and mounts as a **microfrontend** in the hugr platform's shell. Day to day, administrators still manage
with SQL from DuckDB; the console is the second way.

The design: the canvas "tresor console" (claude.ai artifact `KmAQuTDq9uNBePVhoJ49dZ`), on the Hugr Lab design
system. The design brief: `design/ui-prompt.md` (local).

## Problem

- Managing secrets only through SQL gives no overview: what exists, who may use what, which references point
  where, which would break after a configuration change.
- The hugr platform gathers its services (duckdb-acl nodes, an extension registry, tresor) in one shell; tresor
  has nothing to show there.

## Design

### Who uses it

- **Administrators only** (`policy.admins`). Anyone else is refused at sign-in. What their roles are granted
  reaches them in DuckDB, not in the console.
- No new right: the console calls the protocol's routes with the administrator's own token, and the console's
  own routes (below) for what the protocol does not give.

### The console

- **Screens**: secrets (list, detail, editor), variables (list, detail, editor), dynamic secrets
  (`token_exchange`), Access (grants by role and group), the references check, the service.
- **Stack**: React 18, TypeScript, Vite, Tailwind, react-router, Lucide icons, `oidc-client-ts`. No component
  library: Radix's scroll lock injects `<style>` tags, which the CSP refuses; dialogs are native `<dialog>`s
  (their own focus trap and Escape), menus are small components. Every dependency MIT, ISC or Apache-2.0; fonts SIL OFL (Manrope, JetBrains Mono), bundled,
  never from a CDN.
- **Source** in `web/console/`; the build (`dist/`, `dist-mfe/`) is embedded in the binary (`go:embed`), as hub's
  console is. The image builds it in its own stage; `go build` alone embeds a placeholder page.
- **Size**: a desktop console, at least 1280 × 800 px; below that the page scrolls. The microfrontend's content
  keeps at least 960 px.
- **Lists** (`GET /v1/secrets`, `/v1/variables`: every descriptor, no values) are filtered, searched and paged
  in the browser.

### Serving and signing in

- `GET /ui/*`: the build, with an SPA fallback; public, as `/healthz` is.
- `GET /ui/config.json`, public: `{issuers: [{issuer, client_id, scopes, audience}], environment}`, from the
  issuers that have a `client_id` (the public client people log in with: tresor's human flows).
- **Login**: OIDC Authorization Code + PKCE in the browser, against the issuer's public client. The redirect URI
  `<public_url>/ui/callback` must be registered at the IdP. The access token is kept in memory (the PKCE state in
  `sessionStorage`), sent as `Authorization: Bearer`; renewed by the IdP's refresh token. When the session ends,
  a banner signs in again in a popup: the page and an editor's input stay. A reload signs in again through the
  IdP's own session (the issuer used last in the tab), with no prompt when it has one.
- **Headers** on `/ui/`: a Content-Security-Policy (`default-src 'self'`; `connect-src 'self'`, the issuers'
  origins and `ui.connect_src`; no inline script; no frame: the token is renewed by a refresh, never in a hidden
  frame; a component that injects `<style>` takes the page's nonce; `frame-ancestors` from `ui.frame_ancestors`, `'none'` by default),
  `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`.

### Configuration

```yaml
ui:
  enabled: true                 # default; false: no /ui/, no /admin/v1
  environment: prod             # optional: the badge in the top bar; unset, none
  allowed_origins: []           # the microfrontend's hosts (CORS on /v1 and /admin/v1)
  frame_ancestors: []           # pages that may frame /ui/ (CSP); none by default
  connect_src: []               # more origins the sign-in calls (an IdP's endpoints on another host)
```

### The console's API: `/admin/v1`

tresor-server's own routes, **not** part of `duckdb-secrets/1`; administrators only (`403 no_verb` otherwise);
never through a delegation grant (`403 actor_not_allowed`). Every request is audited: `inspect` (the level
`changes` keeps refusals only), `reveal` (always kept), `write` (the params merge).

- `GET /admin/v1/service`: version, protocol, capabilities, the issuers (public settings), the reference sources
  with their kind, connection summary (address, login method; never a token or a key) and allowlist, the KEK's
  kind and current version id, readiness with each check's state.
- `GET /admin/v1/{secrets|variables}/{name}/shape[?values=1]` →
  `{version, params: [{name, type, redacted, reference, value?}]}`:
  - `reference`: the reference as written (a location, never its value);
  - `value`: only with `values=1`, only for a parameter **not** in `redact_keys` and not a reference. Secret
    parameters and the values behind references are never returned, to anyone. Audited as `reveal`.
  - The params merge never unmarks a kept parameter: a mark goes only with a value set anew, so no value the
    administrator never saw can become visible.
- `PATCH /admin/v1/secrets/{name}/params` with `If-Match` →
  `{set: {name: value}, keep: [name], remove: [name], redact_keys, comment?}`: a replace that keeps stored values
  the administrator never saw. Merged inside the store's compare-and-set; a parameter neither kept, set nor
  removed is an error (no silent drop). The same checks as a `PUT` (references, allowlists, `token_exchange`).
  Secrets only: a variable is one value the administrator always sees (or its reference), so its `PUT` serves.
- `GET /admin/v1/grants[?principal=]` → the principals that hold grants, with counts; with `principal`, every
  entry it may use (kind, name, grant id, the other principals). Writes go through the protocol's grant routes.
- `POST /admin/v1/refs-check {resolve}` → `{checked, findings: [{kind, name, param, reason}]}`: spec 009's check
  over HTTP, one at a time per replica, each read bounded as the command's; the write deadline extended for it.
  `resolve` reads every reference with the service's identity, never returning a value: an `inspect`.

Writes otherwise use the protocol's routes: `PUT` (create, with `If-None-Match: *`), `DELETE`, `PATCH`
(comment), the grant routes, `DELETE /v1/delegations`.

### The microfrontend

- A second build, `dist-mfe/`: one ES module and its stylesheet, served at `/ui/mfe/`.
- `mountTresor(element, {apiBase, getToken(audience), theme, basePath, onNavigate, onTitle})` →
  `{update, unmount}`; and `<tresor-console>` (Shadow DOM; the token through a property, never an attribute).
- The host owns sign-in, navigation and the theme; the console renders its content with its own section tabs.
- **Its token** carries tresor's audience: the IdP adds it to the host's tokens (a Keycloak audience mapper, a
  ZITADEL project) or the host gets one for tresor; `getToken(audience)` covers both.
- **CORS** on `/v1/*` and `/admin/v1/*` for `ui.allowed_origins` only (bearer tokens, no cookies); or the host
  proxies tresor under its own origin and needs none.

## Enforcement & security

- **Administrators only**, checked by the service on every `/admin/v1` call, never by the console alone.
- **Values** (a decision of the owner, 2026-10-05): administrators may see the parameters **not** in
  `redact_keys`, on request and audited. This loosens tresor spec 009's "administrators never see material"
  for tresor-server's own console; the protocol is unchanged, and DuckDB's routes behave as before.
  - `redact_keys` is each secret's own: DuckDB sets it from the secret type when written from SQL; the console's
    "secret" toggle sets it (on by default for known names: `password`, `secret`, `token`, `client_secret`,
    `account_key`, …); the service adds every reference's parameter.
  - A parameter left unmarked by its writer is shown: the editor says so.
- **No token in storage**: the access token stays in memory; only the PKCE state is in `sessionStorage`.
- **Fail closed**: a shape with a value that should not be there is a bug the tests look for; a merge with an
  unknown key is refused.
- **The microfrontend** is CORS-limited to configured origins; `/ui/` is not framed except by
  `ui.frame_ancestors`.

## Testing

- Go: `/admin/v1` refuses non-administrators and delegated calls; a shape never carries a redacted or a
  reference's value, with or without `values=1`; `reveal` is audited; the params merge (keep, set, remove,
  unknown key refused, a concurrent write → 412); grants by principal; the refs check; CORS only for allowed
  origins; CSP and headers on `/ui/`.
- The console: unit tests (Vitest); end to end (Playwright) against a service with the CI's mock issuer: sign in,
  create, replace keeping a secret value, grant, delete, the references check, a non-administrator refused.
- The microfrontend mounted in a test host page.

## The PRs

1. **(a)** `/admin/v1` (service, shape, params merge, grants, refs-check), `ui:` configuration, CORS, the
   embedded placeholder at `/ui/`, `/ui/config.json`.
2. **(b)** the console: sign-in, secrets, variables, Access, the references check, the service.
3. **(c)** the microfrontend build and its test host.
4. **(d)** the docs (a Console page; the IdP's redirect URI), the chart (`ui:`), the image's build stage, the
   end-to-end run in CI.

## Alternatives considered

- **A server-rendered UI (Go templates, a cookie session)**: no SPA build, but a session and CSRF to keep, and
  no microfrontend. Rejected.
- **The protocol's routes only**: administrators could not see names or keep values on a replace. Rejected.
- **A token in `localStorage`**: survives a reload, readable by any script on the origin. Rejected.

## Follow-ups

- The decision on values noted in tresor's spec 009 (tresor-server's console may show unredacted parameters to
  administrators).
- An audit view in the console (the audit stream is stdout and OTLP today).
