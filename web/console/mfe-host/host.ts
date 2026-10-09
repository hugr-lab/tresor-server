// A test host for the microfrontend (spec 010, c): another origin, its own sign-in and navigation, tresor's module
// loaded from the service as a platform would. Configured by VITE_TRESOR_URL, VITE_ISSUER, VITE_CLIENT_ID and
// VITE_AUDIENCE (see the README). Not part of the build the service serves.
import { UserManager, WebStorageStateStore, InMemoryWebStorage } from 'oidc-client-ts'

const env = import.meta.env
const tresor = (env.VITE_TRESOR_URL as string).replace(/\/$/, '')
const base = '/platform/tresor'
const users = new UserManager({
  authority: env.VITE_ISSUER as string,
  client_id: env.VITE_CLIENT_ID as string,
  redirect_uri: `${location.origin}/platform/callback`,
  scope: 'openid',
  userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
})
const $ = (id: string) => document.getElementById(id)!
let theme: 'light' | 'dark' = 'light'
let handle: { update(o: { theme?: 'light' | 'dark'; path?: string }): void; unmount(): void } | undefined
let token = ''
// the token's life, simulated for the end-to-end (spec 016): expired (renewed when asked), or revoked (refused even
// renewed, until restored)
let expired = false
let revoked = false
let told = 0

async function signIn() {
  sessionStorage.setItem('host.return', location.pathname)
  await users.signinRedirect()
}

async function show(path: string) {
  $('title').textContent = ''
  if (!path.startsWith(base)) {
    handle?.unmount()
    handle = undefined
    $('title').textContent = 'Home'
    return
  }
  if (!token) return void ($('status').textContent = 'sign in first')
  if (handle) return handle.update({ path })
  const { mountTresor } = await import(/* @vite-ignore */ `${tresor}/ui/mfe/tresor.js`)
  handle = mountTresor($('slot'), {
    apiBase: tresor,
    getToken: async (_audience?: string, how?: { renew?: boolean }) => {
      if (revoked) return 'revoked'
      if (expired && !how?.renew) return 'expired'
      expired = false
      return token
    },
    onUnauthorized: () => ($('status').textContent = `tresor: session ended (${++told})`),
    theme,
    basePath: base,
    onNavigate: (p: string, how: { replace: boolean }) => history[how.replace ? 'replaceState' : 'pushState'](null, '', p),
    onTitle: (t: string) => ($('title').textContent = `tresor · ${t}`),
  })
}

document.addEventListener('click', (e) => {
  const a = (e.target as HTMLElement).closest<HTMLAnchorElement>('a[data-host]')
  if (!a) return
  e.preventDefault()
  history.pushState(null, '', a.pathname)
  void show(a.pathname)
})
addEventListener('popstate', () => void show(location.pathname))
$('theme').onclick = () => {
  theme = theme === 'light' ? 'dark' : 'light'
  document.body.classList.toggle('dark', theme === 'dark')
  handle?.update({ theme })
}
$('signin').onclick = () => void signIn()
$('expire').onclick = () => (expired = true)
$('revoke').onclick = () => (revoked = true)
$('restore').onclick = () => {
  revoked = false
  $('status').textContent = 'signed in'
}
$('brand').onclick = () => $('slot').classList.toggle('branded')

if (location.pathname === '/platform/callback') {
  const user = await users.signinRedirectCallback()
  token = user.access_token
  history.replaceState(null, '', sessionStorage.getItem('host.return') || '/platform/home')
}
$('status').textContent = token ? 'signed in' : 'not signed in'
void show(location.pathname)
