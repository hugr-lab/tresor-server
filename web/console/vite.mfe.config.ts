import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The microfrontend (spec 010, c): one ES module, dist/mfe/tresor.js, exporting mountTresor and defining
// <tresor-console>; served at <public_url>/ui/mfe/ (CORS for ui.allowed_origins). Its styles travel inside it, for
// its shadow root; fonts are files beside it, named relative to the module.
export default defineConfig({
  plugins: [react()],
  base: './',
  publicDir: false, // the page's favicon is the page's
  define: { 'process.env.NODE_ENV': JSON.stringify('production') },
  build: {
    outDir: 'dist/mfe',
    emptyOutDir: true,
    assetsDir: 'assets',
    sourcemap: false,
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    rollupOptions: {
      input: 'src/mfe.tsx',
      preserveEntrySignatures: 'strict',
      output: { format: 'es', entryFileNames: 'tresor.js', inlineDynamicImports: true },
    },
  },
})
