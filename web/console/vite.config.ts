import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The console (spec 010): built into dist/, embedded by the Go binary (web/console/console.go) and served at
// <public_url>/ui/. Files are named relative to the page's <base href>, which the server sets: the service may
// live below a path. No inline script, no eval: the page runs under script-src 'self'.
export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsDir: 'assets',
    sourcemap: false,
    modulePreload: { polyfill: false }, // the polyfill is an inline script
    assetsInlineLimit: 0, // a font inlined as data: is refused by font-src 'self': every asset a file
  },
  server: {
    proxy: { '/v1': 'http://127.0.0.1:8080', '/admin': 'http://127.0.0.1:8080', '/ui/config.json': 'http://127.0.0.1:8080' },
  },
  test: { environment: 'jsdom', include: ['src/**/*.test.{ts,tsx}'] }, // e2e/ is Playwright's
} as never)
