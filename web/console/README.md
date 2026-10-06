# tresor console

The management console (spec 010): a React app built into `dist/`, embedded by the Go binary
(`console.go`), served at `<public_url>/ui/`. Administrators only.

```sh
npm ci
npm run dev          # Vite on :5173, /v1 and /admin proxied to a service on 127.0.0.1:8080
npm test             # Vitest
npm run typecheck
npm run licenses     # every shipped package permissive (MIT, ISC, Apache-2.0, BSD, OFL)
npm run build        # dist/ and dist/mfe/: then `go build ./cmd/tresor-server` embeds them
npm run host         # the microfrontend's test host on 127.0.0.1:18444 (below)
../../scripts/ci/console-e2e.sh   # end to end: Keycloak in docker, the service, the test host, Playwright
                     # (once: npx playwright install chromium)
```

- `dist/index.html` in git is a placeholder: `go build` alone serves it. A local `npm run build` replaces it;
  do not commit the build. The image builds the console in its own stage.
- The page runs under a strict CSP (`script-src 'self'`, `style-src 'self'`): no inline script or style tag,
  no component that injects one. Dialogs are native `<dialog>`s.
- Sign-in: OIDC Authorization Code + PKCE (`oidc-client-ts`), the token in memory; the issuer's public client
  needs `<public_url>/ui/callback` as a redirect URI.
- Look: the Hugr Lab design system (tokens in `src/styles.css`), Manrope and JetBrains Mono (SIL OFL, bundled),
  Lucide icons (ISC).

## The microfrontend

`dist/mfe/tresor.js` (served at `<public_url>/ui/mfe/tresor.js`) is one ES module for a host's shell, such as the
hugr platform. The host owns sign-in, navigation and the theme; the console draws into the element's shadow root
with its own styles (constructed style sheets: the host's CSP needs no `'unsafe-inline'`) and its section tabs.

```js
const { mountTresor } = await import('https://tresor.example/ui/mfe/tresor.js')
const tresor = mountTresor(element, {
  apiBase: 'https://tresor.example',          // the service's public_url
  getToken: async (audience) => token,         // called before each request: an access token for tresor
  audience: 'duckdb-secrets',                  // optional: passed to getToken when the host asks per audience
  theme: 'dark',
  basePath: '/platform/tresor',                // the host's path the console lives under
  onNavigate: (path, { replace }) => history[replace ? 'replaceState' : 'pushState'](null, '', path), // optional:
                                               // else the console keeps the browser's history itself
  onTitle: (title) => setBreadcrumb(title),
})
tresor.update({ theme: 'light' })              // the host's theme changed
tresor.update({ path: location.pathname })     // the host navigated (its back button)
tresor.unmount()
```

Or as an element: `<tresor-console api-base="…" base-path="…" audience="…" theme="dark">`, mounted once its
`getToken` **property** is set (a token is never an attribute); `tresor-navigate` and `tresor-title` events, or
`onNavigate` and `onTitle` properties; `navigate(path)` for the host's own navigation.

The service sends CORS headers for `ui.allowed_origins` on `/ui/mfe/`, `/v1/` and `/admin/v1/`. The host's CSP
allows the service's origin in `script-src`, `font-src` and `connect-src`. One element holds one console.

- The fonts' faces (`Manrope`, `JetBrains Mono`) are added to the host's document once (a shadow root's are not
  used); a host using those family names for its own text gets tresor's files.
- Menus and toasts are `position: fixed`: an ancestor with `transform`, `filter` or `contain` moves them. A token must carry tresor's audience:
the IdP adds it to the host's tokens (a Keycloak audience mapper, a ZITADEL project) or the host asks for one.

**The test host** (`mfe-host/`, not shipped): another origin with its own sign-in, loading the module from a
running service. Set in `.env.local` (gitignored):

```sh
VITE_TRESOR_URL=http://127.0.0.1:18443        # the service, with ui.allowed_origins: [http://127.0.0.1:18444]
VITE_ISSUER=http://127.0.0.1:18090/realms/tresor
VITE_CLIENT_ID=tresor-console                 # a public client with http://127.0.0.1:18444/platform/* as a redirect URI
```
