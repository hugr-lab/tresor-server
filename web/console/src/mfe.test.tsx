// The microfrontend mounted as a host would (spec 010, c): in the element's shadow root, the token from the host,
// the host told where the console went, the theme and the path from the host.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { act } from 'react'
import { mountTresor, TresorConsole } from './mfe'

const service = { version: 'test', protocol: 'duckdb-secrets/1', environment: '', capabilities: [], state: 'memory', kek: { kind: 'local' },
  issuers: [], sources: [], policy: { admins: ['role:secrets_admin'], actors: [] }, audit: 'all', ready: { ready: true, checks: {} } }
const me = { subject: 'anna', roles: ['role:secrets_admin'], groups: [], permissions: { create: true } }

function answer(status: number, body: unknown) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))
}

function stub(admin = true) {
  const calls: { url: string; auth: string | null }[] = []
  vi.stubGlobal('fetch', (url: string, init: RequestInit) => {
    calls.push({ url, auth: new Headers(init.headers).get('Authorization') })
    if (url.endsWith('/v1/whoami')) return answer(200, me)
    if (url.endsWith('/admin/v1/service')) return admin ? answer(200, service) : answer(403, { title: 'no_verb', status: 403 })
    if (url.endsWith('/v1/secrets') || url.endsWith('/v1/variables')) return answer(200, [])
    return answer(404, { title: 'not_found', status: 404 })
  })
  return calls
}

// jsdom has no modal dialogs
HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) { this.open = true }
HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) { this.open = false }

const settle = () => act(() => new Promise((r) => setTimeout(r, 20)))

afterEach(() => {
  vi.unstubAllGlobals()
  document.body.innerHTML = ''
  window.history.replaceState(null, '', '/')
})

describe('mountTresor', () => {
  it('renders in a shadow root with the host token and tells the host the section', async () => {
    const calls = stub()
    window.history.replaceState(null, '', '/platform/tresor/variables')
    const el = document.createElement('div')
    document.body.appendChild(el)
    const titles: string[] = []
    const navigated: string[] = []
    const getToken = vi.fn(async (aud?: string) => `tok-${aud}`)
    let h!: ReturnType<typeof mountTresor>
    await act(async () => {
      h = mountTresor(el, { apiBase: 'https://tresor.example/', getToken, audience: 'duckdb-secrets', basePath: '/platform/tresor/', theme: 'dark',
        onNavigate: (p, how) => navigated.push(how.replace ? `${p} (replace)` : p), onTitle: (t) => titles.push(t) })
    })
    await settle()
    expect(el.shadowRoot).not.toBeNull()
    expect(el.childNodes.length).toBe(0) // nothing in the host's light DOM
    expect(calls[0]).toEqual({ url: 'https://tresor.example/v1/whoami', auth: 'Bearer tok-duckdb-secrets' })
    expect(getToken).toHaveBeenCalledWith('duckdb-secrets')
    const frame = el.shadowRoot!.querySelector<HTMLElement>('.mfe-root')!
    expect(frame.dataset.theme).toBe('dark')
    expect(el.dataset.tresorTheme).toBe('dark') // the variables' dark defaults are on :host, under the host's own
    expect(el.shadowRoot!.querySelector('nav[aria-label="tresor"]')).not.toBeNull() // its own section tabs, no sidebar
    expect(titles.at(-1)).toBe('Variables')
    expect(navigated).toEqual([]) // where the host already is: nothing to tell
    await act(async () => h.update({ theme: 'light', path: '/platform/tresor/service' }))
    await settle()
    expect(frame.dataset.theme).toBe('light')
    expect(titles.at(-1)).toBe('Service')
    expect(navigated).toEqual([]) // the host's own navigation is not echoed back
    const access = [...el.shadowRoot!.querySelectorAll('a')].find((a) => a.textContent === 'Access')!
    await act(async () => access.click())
    await settle()
    expect(navigated).toEqual(['/platform/tresor/access'])
    expect(titles.at(-1)).toBe('Access') // stays: the host's earlier path is not applied again
    expect(() => mountTresor(el, { apiBase: 'https://tresor.example', getToken })).toThrow(/already/)
    await act(async () => h.unmount())
    expect(el.shadowRoot!.childElementCount).toBe(0)
    expect(el.dataset.tresorTheme).toBeUndefined()
    expect(() => h.update({ theme: 'dark' })).not.toThrow() // after unmount: nothing
    await act(async () => {
      h = mountTresor(el, { apiBase: 'https://tresor.example', getToken })
    })
    await settle()
    expect(el.shadowRoot!.querySelectorAll('.mfe-root').length).toBe(1) // mounted again
    await act(async () => h.unmount())
  })

  it('keeps the browser history itself without onNavigate, and tells the host its path when at basePath alone', async () => {
    stub()
    window.history.replaceState(null, '', '/app')
    const el = document.createElement('div')
    document.body.appendChild(el)
    const told: string[] = []
    await act(async () => {
      mountTresor(el, { apiBase: 'https://tresor.example', getToken: async () => 't', basePath: '/app', onTitle: (t) => told.push(t) })
    })
    await settle()
    expect(window.location.pathname).toBe('/app/secrets') // replaced, not pushed
    const vars = [...el.shadowRoot!.querySelectorAll('a')].find((a) => a.textContent === 'Variables')!
    await act(async () => vars.click())
    await settle()
    expect(window.location.pathname).toBe('/app/variables')
    await act(async () => {
      window.history.replaceState(null, '', '/app/service')
      window.dispatchEvent(new PopStateEvent('popstate'))
    })
    await settle()
    expect(told.at(-1)).toBe('Service')
  })

  it('refuses a non-administrator, and needs the token function', async () => {
    stub(false)
    const el = document.createElement('div')
    document.body.appendChild(el)
    expect(() => mountTresor(el, { apiBase: 'https://tresor.example' } as never)).toThrow(/getToken/)
    await act(async () => {
      mountTresor(el, { apiBase: 'https://tresor.example', getToken: async () => 't' })
    })
    await settle()
    expect(el.shadowRoot!.textContent).toMatch(/managed by administrators/)
  })
})

describe('<tresor-console>', () => {
  it('takes properties a host set before the element was defined', async () => {
    stub()
    const el = document.createElement('tresor-console-pending') as HTMLElement & Record<string, unknown>
    el.setAttribute('api-base', 'https://tresor.example')
    const titles: string[] = []
    el.getToken = async () => 't'
    el.onTitle = (t: string) => titles.push(t)
    document.body.appendChild(el)
    await act(async () => {
      customElements.define('tresor-console-pending', class extends TresorConsole {})
    })
    await settle()
    expect(el.shadowRoot!.querySelector('.mfe-root')).not.toBeNull()
    expect(titles.at(-1)).toBe('Secrets')
    await act(async () => {
      el.getToken = undefined // no token function: unmounted
    })
    expect(el.shadowRoot!.childElementCount).toBe(0)
  })

  it('mounts once the token function is given as a property, never from an attribute', async () => {
    stub()
    const el = document.createElement('tresor-console') as TresorConsole
    el.setAttribute('api-base', 'https://tresor.example')
    el.setAttribute('getToken', 'not-a-function')
    await act(async () => document.body.appendChild(el))
    expect(el.shadowRoot).toBeNull()
    const seen: string[] = []
    el.addEventListener('tresor-title', (e) => seen.push((e as CustomEvent<string>).detail))
    await act(async () => {
      el.getToken = async () => 't'
    })
    await settle()
    expect(el.shadowRoot!.querySelector('.mfe-root')).not.toBeNull()
    expect(seen.at(-1)).toBe('Secrets')
    await act(async () => el.remove())
    expect(el.shadowRoot!.childElementCount).toBe(0)
  })
})

// spec 016: the contract's version; a refused token renewed once; a session over told to the host (at most once
// per 30 s) and shown; the console works again once a request passes
describe('the platform contract (spec 016)', () => {
  it('exports its version and names it on the element', async () => {
    const mod = await import('./mfe')
    expect(mod.contract).toBe(1)
    stub()
    const el = document.createElement('tresor-console') as TresorConsole
    document.body.appendChild(el)
    expect(el.dataset.contract).toBe('1')
  })

  it('renews a refused token once, then tells the host', async () => {
    // the service accepts only tokens named "good"
    let accepted = 'good'
    vi.stubGlobal('fetch', (url: string, init: RequestInit) => {
      if (new Headers(init.headers).get('Authorization') !== `Bearer ${accepted}`) return answer(401, { title: 'unauthenticated', status: 401 })
      if (url.endsWith('/v1/whoami')) return answer(200, me)
      if (url.endsWith('/admin/v1/service')) return answer(200, service)
      return answer(200, [])
    })
    const el = document.createElement('div')
    document.body.appendChild(el)
    let cached = 'stale'
    const asked: (boolean | undefined)[] = []
    const getToken = vi.fn(async (_a?: string, how?: { renew?: boolean }) => {
      asked.push(how?.renew)
      if (how?.renew) cached = 'good'
      return cached
    })
    const told = vi.fn()
    await act(async () => {
      mountTresor(el, { apiBase: 'https://tresor.example', getToken, onUnauthorized: told })
    })
    await settle()
    expect(el.shadowRoot!.querySelector('nav[aria-label="tresor"]')).not.toBeNull() // renewed once, then served
    expect(asked).toContain(true)
    expect(told).not.toHaveBeenCalled()

    // the session over: even renewed, refused - the host told once, the console says so
    accepted = 'never'
    const access = [...el.shadowRoot!.querySelectorAll('a')].find((a) => a.textContent === 'Access')!
    await act(async () => access.click())
    await settle()
    await act(async () => [...el.shadowRoot!.querySelectorAll('a')].find((a) => a.textContent === 'Variables')!.click())
    await settle()
    expect(told).toHaveBeenCalledTimes(1) // at most once per 30 s
    expect(el.shadowRoot!.textContent).toMatch(/Your session ended/)

    // signed in again: the next request passes, the notice goes
    accepted = 'good'
    const retry = [...el.shadowRoot!.querySelectorAll('button')].find((b) => b.textContent === 'Try again')!
    await act(async () => retry.click())
    await settle()
    expect(el.shadowRoot!.textContent).not.toMatch(/Your session ended/)
  })

  it('tells an element host by an event', async () => {
    vi.stubGlobal('fetch', () => answer(401, { title: 'unauthenticated', status: 401 }))
    const el = document.createElement('tresor-console') as TresorConsole
    el.setAttribute('api-base', 'https://tresor.example')
    el.setAttribute('locale', 'de') // not spoken yet: English
    let told = 0
    el.addEventListener('tresor-unauthorized', () => told++)
    document.body.appendChild(el)
    await act(async () => {
      el.getToken = async () => 'refused'
    })
    await settle()
    expect(told).toBe(1)
    expect(el.shadowRoot!.textContent).toMatch(/Your session ended/) // refused at the first load: the notice, not a dead end
  })

  it('renews once for requests refused together; a remount does not tell the host sooner', async () => {
    let accepted = 'good'
    vi.stubGlobal('fetch', (url: string, init: RequestInit) => {
      if (new Headers(init.headers).get('Authorization') !== `Bearer ${accepted}`) return answer(401, { title: 'unauthenticated', status: 401 })
      if (url.endsWith('/v1/whoami')) return answer(200, me)
      if (url.endsWith('/admin/v1/service')) return answer(200, service)
      return answer(200, [])
    })
    const el = document.createElement('div')
    document.body.appendChild(el)
    let renewals = 0
    let cached = 'stale'
    const getToken = async (_a?: string, how?: { renew?: boolean }) => {
      if (how?.renew) {
        renewals++
        await new Promise((r) => setTimeout(r, 5))
        cached = accepted === 'never' ? 'revoked' : accepted // the session over: nothing fresh is accepted
      }
      return cached
    }
    const told = vi.fn()
    let h!: ReturnType<typeof mountTresor>
    await act(async () => {
      h = mountTresor(el, { apiBase: 'https://tresor.example', getToken, onUnauthorized: told })
    })
    await settle()
    expect(el.shadowRoot!.querySelector('nav[aria-label="tresor"]')).not.toBeNull()
    expect(renewals).toBe(1) // whoami and the service, refused together: one renewal (a refresh token is used once)

    accepted = 'never'
    await act(async () => h.unmount())
    await act(async () => {
      h = mountTresor(el, { apiBase: 'https://tresor.example', getToken, onUnauthorized: told })
    })
    await settle()
    expect(told).toHaveBeenCalledTimes(1)
    expect(el.shadowRoot!.textContent).toMatch(/Your session ended/)
    await act(async () => h.unmount())
    await act(async () => {
      mountTresor(el, { apiBase: 'https://tresor.example', getToken, onUnauthorized: told })
    })
    await settle()
    expect(told).toHaveBeenCalledTimes(1) // the same element, within 30 s

    accepted = 'good'
    cached = 'good'
    const retry = [...el.shadowRoot!.querySelectorAll('button')].find((b) => b.textContent === 'Try again')!
    await act(async () => retry.click())
    await settle()
    expect(el.shadowRoot!.querySelector('nav[aria-label="tresor"]')).not.toBeNull() // the first load, once more
    expect(el.shadowRoot!.textContent).not.toMatch(/Your session ended/)
  })
})
