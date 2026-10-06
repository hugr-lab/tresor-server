// The console end to end (spec 010, d): sign-in at Keycloak, the secrets' life (create, show, replace keeping a
// secret value, grant, delete), the references check, a non-administrator refused, the session ended and renewed
// in a popup with an editor's input kept, and the microfrontend in a host on another origin.
import { expect, test, type Page } from '@playwright/test'

const env = (k: string) => {
  const v = process.env[k]
  if (!v) throw new Error(`${k} is not set: run scripts/ci/console-e2e.sh`)
  return v
}

/** Keycloak's login form, in a page or a popup */
async function login(page: Page, user: string, password: string) {
  await page.locator('#username').fill(user)
  await page.locator('#password').fill(password)
  await page.locator('#kc-login').click()
}

async function signIn(page: Page, user: string, password: string) {
  await page.goto('/ui/')
  await page.getByRole('button', { name: /Sign in with/ }).click()
  await login(page, user, password)
}

const value = (page: Page, name: string) => page.locator(`input[aria-label="${name}: value"]`)

test('a non-administrator is refused', async ({ page }) => {
  await signIn(page, 'jonas', env('E2E_USER_PW'))
  await expect(page.getByRole('heading', { name: 'The console is for administrators' })).toBeVisible()
  await expect(page.getByText('role:analysts')).toBeVisible()
})

test("a secret's life: create, show, replace keeping the secret value, grant, delete", async ({ page }) => {
  // what the service answers, not only what the page draws: a secret value is never in an answer
  const answers: Promise<string>[] = []
  page.on('response', (r) => {
    if (/\/(admin\/)?v1\//.test(new URL(r.url()).pathname)) answers.push(r.text().catch(() => ''))
  })
  await signIn(page, 'anna', env('E2E_ADMIN_PW'))
  await expect(page.getByRole('heading', { name: 'Secrets' })).toBeVisible()

  await page.getByRole('link', { name: 'New secret' }).click()
  await page.getByRole('textbox', { name: /^Name/ }).fill('e2e-pg')
  await page.getByRole('combobox', { name: 'Secret type' }).fill('postgres')
  await page.getByRole('combobox', { name: 'Secret type' }).press('Enter')
  await value(page, 'host').fill('db.internal')
  await value(page, 'user').fill('etl')
  await value(page, 'password').fill('e2e-hunter2')
  await expect(page.getByLabel('password is secret')).toBeChecked() // a known name: secret by default
  await expect(page.getByLabel('SQL preview')).not.toContainText('e2e-hunter2')
  await page.getByRole('button', { name: 'Create' }).click()

  await expect(page).toHaveURL(/\/ui\/secrets\/e2e-pg$/)
  await page.getByRole('button', { name: 'Show values' }).click()
  await expect(page.getByText('db.internal')).toBeVisible()
  await expect(page.locator('body')).not.toContainText('e2e-hunter2') // a secret value is never shown

  await page.getByRole('link', { name: 'Replace' }).click()
  await expect(page.getByRole('radio', { name: 'Keep' }).first()).toBeVisible()
  await page.getByRole('radiogroup', { name: 'host: value' }).getByRole('radio', { name: 'Value' }).click()
  await value(page, 'host').fill('db2.internal')
  await page.getByRole('button', { name: /Save as v2/ }).click()
  await expect(page).toHaveURL(/\/ui\/secrets\/e2e-pg$/)
  await page.getByRole('button', { name: 'Show values' }).click()
  await expect(page.getByText('db2.internal')).toBeVisible()
  await expect(page.getByText('secret: never shown')).toBeVisible() // the password kept, still secret

  const grants = page.getByRole('region', { name: 'Grants' })
  await grants.getByPlaceholder('role:… or group:…').fill('role:analysts')
  await grants.getByRole('button', { name: 'Grant' }).click()
  await expect(grants.getByText('role:analysts')).toBeVisible()

  await page.getByRole('link', { name: /^Secrets/ }).first().click()
  await page.getByRole('button', { name: 'Actions for e2e-pg' }).click()
  await page.getByRole('menuitem', { name: 'Delete…' }).click()
  const dialog = page.getByRole('dialog')
  await dialog.locator('input').fill('e2e-pg')
  await dialog.getByRole('button', { name: /Delete/ }).click()
  await expect(page.getByText('No secrets yet')).toBeVisible()
  const bodies = await Promise.all(answers)
  expect(bodies.length).toBeGreaterThan(5)
  expect(bodies.filter((b) => b.includes('e2e-hunter2'))).toEqual([])
})

test('the references check runs', async ({ page }) => {
  await signIn(page, 'anna', env('E2E_ADMIN_PW'))
  await page.getByRole('link', { name: 'References check' }).click()
  await page.getByRole('button', { name: 'Check', exact: true }).click()
  await expect(page.getByText('Every reference resolves as configured.')).toBeVisible()
})

test("the session ends: signed in again in a popup, the editor's input kept", async ({ page, context, request }) => {
  test.setTimeout(180_000)
  await signIn(page, 'anna', env('E2E_ADMIN_PW'))
  await page.getByRole('link', { name: 'New secret' }).click()
  await page.getByRole('textbox', { name: /^Name/ }).fill('typed-before-the-end')

  // the IdP ends anna's sessions: the refresh fails, the token runs out (90 s in the test realm)
  const kc = env('E2E_KEYCLOAK_URL')
  const admin = await request.post(`${kc}/realms/master/protocol/openid-connect/token`, {
    form: { client_id: 'admin-cli', grant_type: 'password', username: env('E2E_KC_ADMIN'), password: env('E2E_KC_ADMIN_PW') },
  })
  const token = (await admin.json()).access_token as string
  const users = await (await request.get(`${kc}/admin/realms/tresor/users?username=anna&exact=true`, { headers: { Authorization: `Bearer ${token}` } })).json()
  const out = await request.post(`${kc}/admin/realms/tresor/users/${users[0].id}/logout`, { headers: { Authorization: `Bearer ${token}` } })
  expect(out.ok()).toBeTruthy()

  await expect(page.getByText('Your session ended. Your edit is kept.')).toBeVisible({ timeout: 120_000 })
  const popup = context.waitForEvent('page')
  await page.getByRole('button', { name: 'Sign in again' }).click()
  const p = await popup
  const closed = p.waitForEvent('close')
  await login(p, 'anna', env('E2E_ADMIN_PW'))
  await closed
  await expect(page.getByText('Your session ended')).toBeHidden()
  await expect(page.getByRole('textbox', { name: /^Name/ })).toHaveValue('typed-before-the-end')
})

test('the microfrontend in a host on another origin', async ({ page }) => {
  const host = env('E2E_HOST_URL')
  await page.goto(`${host}/platform/tresor/secrets`)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await login(page, 'anna', env('E2E_ADMIN_PW'))
  await expect(page.locator('#title')).toHaveText('tresor · Secrets')
  const tabs = page.locator('#slot').getByRole('navigation', { name: 'tresor' }) // Playwright pierces the shadow root
  await tabs.getByRole('link', { name: 'Variables' }).click()
  await expect(page).toHaveURL(/\/platform\/tresor\/variables$/)
  await expect(page.locator('#title')).toHaveText('tresor · Variables')
  await page.goBack()
  await expect(page.locator('#title')).toHaveText('tresor · Secrets')
  await tabs.getByRole('link', { name: 'Access' }).click()
  // the host's earlier path is not applied again: still on Access once things settle
  await expect(page).toHaveURL(/\/platform\/tresor\/access$/)
  await page.waitForTimeout(800)
  await expect(page).toHaveURL(/\/platform\/tresor\/access$/)
  await expect(page.locator('#title')).toHaveText('tresor · Access')
  await expect(page.locator('#slot').getByRole('region', { name: 'Roles and groups' })).toBeVisible()
  await page.locator('#theme').click()
  await expect(page.locator('#slot .mfe-root')).toHaveAttribute('data-theme', 'dark')
})
