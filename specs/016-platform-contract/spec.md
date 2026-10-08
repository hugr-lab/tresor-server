# Spec 016: the console in the hugr platform - the microfrontend's contract, version 1

- **Status**: draft
- **Date**: 2026-10-08
- **Author**: hugr lab

## Summary

The hugr platform will have one user interface that mounts its components' microfrontends; tresor-server's console
is one (spec 010, c). Its contract exists (`mountTresor`, `<tresor-console>`) but was written for a test host.
This makes it a stable, versioned contract a platform built separately can rely on: a contract version, the host
told when its token is refused, the module cached safely across upgrades, a documented way to know before mounting
whether the user may use it, theming by CSS variables, and a reserved `locale`.

## Problem

Checked against what a platform shell needs (2026-10-08):

- **A token refused mid-session** (expired, revoked) shows an error inside the console; the host is not told, so it
  cannot renew the token or send the user to sign in.
- **`/ui/mfe/tresor.js` has no caching headers**: its name is fixed, and the files are embedded with no
  modification time, so there is no `Last-Modified` and no `ETag` - a browser may keep an old module after an
  upgrade, by heuristics.
- **No version**: the platform and tresor-server are upgraded on their own schedules; nothing says which contract a
  module implements.
- **Whether to show the entry**: the console is for administrators; the platform has no documented way to know
  before mounting.
- **Theming**: the console's colours are CSS variables on `:host`, which the host's styles already override - but
  that is not part of the contract, nor are the variables' names.
- **Language**: English only; the platform will switch languages later.

## Design

### The contract, version 1

```ts
const tresor = await import(`${apiBase}/ui/mfe/tresor.js`)
tresor.contract            // 1: this spec; a breaking change is 2, an addition stays 1
const h = tresor.mountTresor(element, {
  apiBase, getToken, audience?, theme?, basePath?, onNavigate?, onTitle?,
  onUnauthorized?,         // new: the service refused the token (401); the host renews it or signs the user in
  locale?,                 // new: 'en' (the only one now); another falls back to 'en'
})
h.update({ theme?, path?, locale? })
h.unmount()
```

- **`contract`**: an exported number, and `data-contract` on `<tresor-console>`. Additions (a new option, a new
  event) keep 1; a change that breaks a host is 2, announced in the release notes.
- **`onUnauthorized()`**: called when the service answers 401 to a request, at most once per 30 seconds. The
  console first calls `getToken(audience, { renew: true })` once and retries the request; only if that is refused
  too is `onUnauthorized` called, and the screen shows "Your session ended" until a request succeeds again. On the
  element: the `tresor-unauthorized` event.
- **`getToken(audience, { renew })`**: the second argument is new and optional; a host that ignores it keeps
  working (its token is used again, refused again, and `onUnauthorized` follows).
- **`locale`**: reserved now, so adding languages later is not a contract change; `'en'` only.

### Knowing before mounting

`GET <apiBase>/v1/whoami` with the user's token: `permissions.create` is `true` for an administrator (the protocol's
own answer, tresor specs/009). The platform shows the entry when it is true; the contract documents it. Without a
token, or `false`, the entry is hidden; mounted anyway, the console says it is for administrators.

### The module's caching

- `/ui/mfe/tresor.js`: `Cache-Control: no-cache` and an `ETag` (the SHA-256 of its content, computed at start):
  a browser revalidates each load with a cheap 304, and an upgrade is picked up at once.
- `/ui/mfe/assets/*`: hashed names, `immutable`, as now.
- The same for the standalone page's `index.html` (already `no-cache`) - an ETag added.

### Theming

The colours are CSS custom properties; a host sets them on the element and they win over the console's own (the
cascade puts the document's rule above `:host`):

```css
tresor-console, .tresor-mount { --brand: #3a7bd5; --surface: #fff; --ink: #111; }
```

The contract lists them: `--surface`, `--surface-soft`, `--ink`, `--ink-muted`, `--border`, `--brand`,
`--brand-strong`, `--on-brand`, `--focus`, `--success(-soft)`, `--warning(-soft)`, `--danger(-soft)`, `--row`;
`theme` picks the light or dark defaults under them. Fonts: Manrope and JetBrains Mono are added to the document
once (a host using the same families gets these files).

### Layout

The console's content needs at least 960 px wide; below that it scrolls horizontally inside the element. The host
gives it the height it has; the console scrolls within.

### Delivery

- **Same origin, by a proxy** (recommended): the platform serves tresor-server under its own origin
  (`/tresor/...` to the service): no CORS, the platform's CSP allows itself.
- **Another origin**: `ui.allowed_origins` names the platform; its CSP allows tresor-server's origin in
  `script-src`, `font-src`, `connect-src`.
- **The token's audience**: the platform's IdP puts `duckdb-secrets` (the service's `audience`) into its tokens -
  with Keycloak an audience mapper on the platform's client - or the platform asks for one per audience
  (`getToken(audience)`).

### The bundle

One ES module with its own React (~400 KB, ~100 KB gzipped): independent of the platform's framework and version.

## Enforcement & security

- The token stays a function the host gives: never an attribute, never stored, never logged.
- `onUnauthorized` carries no token and no reason text from the service.
- CORS, CSP and the admin-only API are unchanged (spec 010).

## Testing

- Vitest: `contract` exported; a 401 → one `getToken(..., {renew: true})` and a retry; a second 401 →
  `onUnauthorized` once (and not again within 30 s); `locale` other than `en` falls back; the element's
  `data-contract` and `tresor-unauthorized` event.
- Go: `/ui/mfe/tresor.js` has `no-cache` and a strong ETag; `If-None-Match` answers 304.
- Playwright (the test host): theming by a variable set on the element; the token expired in the host → renewed
  through `getToken`; refused again → the host told.

## Alternatives considered

- **Module federation** (shared React with the platform): couples the two builds' versions; the platform is not
  built yet. Rejected for now; the self-contained module can move to it later without a contract change.
- **An iframe**: simpler isolation, but sizing, navigation and the token would cross a frame boundary by
  postMessage - more contract, not less. Rejected.
- **Hashed module names** (`tresor.<hash>.js`, found through a manifest): one more request for the platform, the
  same effect as `no-cache` + ETag. Rejected.

## Open questions

- The platform's IdP (Keycloak assumed) and whether it proxies tresor-server under its own origin - both settled
  when the platform's own spec is.

## Follow-ups

- Languages: the console's text through a catalogue, `locale` honoured (when the platform switches languages).
