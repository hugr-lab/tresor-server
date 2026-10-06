import { defineConfig, devices } from '@playwright/test'

// The console end to end (spec 010, d), against a running service and Keycloak: scripts/ci/console-e2e.sh
// starts them and sets E2E_* (the URLs, the users' passwords). Chromium only: the console is a desktop app.
export default defineConfig({
  testDir: 'e2e',
  timeout: 60_000,
  retries: 0,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: process.env.E2E_TRESOR_URL,
    viewport: { width: 1440, height: 900 },
    // no trace: it records fill()'s values and request bodies - this run's passwords - into a CI artifact;
    // a screenshot draws a password field as dots
    trace: 'off',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } } }],
})
