import { defineConfig } from 'vite'

// The microfrontend's test host (mfe-host/): `npm run host`, on another origin than the service.
export default defineConfig({
  root: 'mfe-host',
  envDir: '..',
  server: { port: Number(process.env.HOST_PORT ?? 18444), strictPort: true, host: '127.0.0.1' },
  appType: 'spa',
  build: { target: 'es2022' },
  esbuild: { target: 'es2022' },
})
