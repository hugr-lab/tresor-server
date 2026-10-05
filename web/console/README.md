# tresor console

The management console (spec 010): a React app built into `dist/`, embedded by the Go binary
(`console.go`), served at `<public_url>/ui/`. Administrators only.

```sh
npm ci
npm run dev          # Vite on :5173, /v1 and /admin proxied to a service on 127.0.0.1:8080
npm test             # Vitest
npm run typecheck
npm run licenses     # every shipped package permissive (MIT, ISC, Apache-2.0, BSD, OFL)
npm run build        # dist/: then `go build ./cmd/tresor-server` embeds it
```

- `dist/index.html` in git is a placeholder: `go build` alone serves it. A local `npm run build` replaces it;
  do not commit the build. The image builds the console in its own stage.
- The page runs under a strict CSP (`script-src 'self'`, `style-src 'self'`): no inline script or style tag,
  no component that injects one. Dialogs are native `<dialog>`s.
- Sign-in: OIDC Authorization Code + PKCE (`oidc-client-ts`), the token in memory; the issuer's public client
  needs `<public_url>/ui/callback` as a redirect URI.
- Look: the Hugr Lab design system (tokens in `src/styles.css`), Manrope and JetBrains Mono (SIL OFL, bundled),
  Lucide icons (ISC).
