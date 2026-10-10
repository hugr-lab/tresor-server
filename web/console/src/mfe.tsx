// The console as a microfrontend (spec 010, c): mountTresor(element, options) and <tresor-console>. The host owns
// sign-in, navigation and the theme; the console renders in the element's shadow root, its styles its own.
import { StrictMode, useEffect, useMemo, useRef, useState } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { MemoryRouter, useLocation, useNavigate, useNavigationType } from 'react-router-dom'
import css from './styles.css?inline'
import { App } from './App'
import { AppContext, type AppState, type Theme } from './context'
import { Api, ApiError } from './lib/api'
import type { ConsoleConfig } from './lib/config'
import type { ServiceInfo, Whoami } from './lib/types'
import { Toasts } from './components/ui'
import { localPath } from './lib/paths'

/** the contract this module implements (spec 016): an addition keeps it, a change that breaks a host raises it */
export const contract = 1

/** the languages the console speaks; another falls back to the first (spec 016: reserved, English for now) */
export const locales = ['en'] as const
export type Locale = (typeof locales)[number]

/** how often onUnauthorized may be called, at most */
const unauthorizedEvery = 30_000
// when each element's host was last told: a remount (the element moved, the host signed in by a redirect) does not
// tell it sooner
const told = new WeakMap<HTMLElement, number>()

export interface TresorOptions {
  /** the service's URL (its public_url): /v1 and /admin/v1 are below it */
  apiBase: string
  /** an access token carrying tresor's audience, called before each request from the host's cache; with renew,
   * after the service refused one: a fresh token, not the cached one */
  getToken: (audience?: string, how?: { renew?: boolean }) => Promise<string>
  /** the audience the host asks for, when its tokens do not carry tresor's already */
  audience?: string
  theme?: Theme
  /** the host's path the console lives under, e.g. /platform/tresor; the console's own paths follow it */
  basePath?: string
  /** the console moved: the host's full path and query, for its address bar and history (replace: the entry is
   * replaced, not added). Without it the console keeps the browser's history itself */
  onNavigate?: (path: string, how: { replace: boolean }) => void
  /** the section shown, for the host's title or breadcrumbs */
  onTitle?: (title: string) => void
  /** the service refused the token even renewed: the session is over - the host signs the user in again (at
   * most once per 30 seconds) */
  onUnauthorized?: () => void
  /** the console's language: 'en' (the only one now) */
  locale?: string
}

export interface TresorHandle {
  /** a new theme, a path the host navigated to (its back button), a language */
  update(options: { theme?: Theme; path?: string; locale?: string }): void
  unmount(): void
}

const titles: [RegExp, string][] = [
  [/^\/secrets/, 'Secrets'], [/^\/create\/secret/, 'New secret'], [/^\/variables/, 'Variables'], [/^\/create\/variable/, 'New variable'],
  [/^\/access/, 'Access'], [/^\/refs/, 'References check'], [/^\/service/, 'Service'],
]

const trim = (p: string) => p.replace(/\/+$/, '')

/** the console's own path (and query) from the host's: below basePath, else the start */
function inner(basePath: string, path: string): string {
  const base = trim(basePath)
  const [p, q] = [path.split('?')[0], path.includes('?') ? path.slice(path.indexOf('?')) : '']
  if (base && p !== base && !p.startsWith(base + '/')) return '/secrets'
  const own = p.slice(base.length)
  return own && own !== '/' && localPath(own) ? own + q : '/secrets'
}

/** the elements mounted: one console per element */
const mounted = new WeakSet<HTMLElement>()

let sheet: CSSStyleSheet | undefined
let fonts = false

/** the styles in a shadow root; the fonts' faces in the document, where a shadow root's @font-face is not used */
function style(root: ShadowRoot): () => void {
  const faces = css.match(/@font-face\s*{[^}]*}/g)?.join('\n') ?? ''
  if (typeof CSSStyleSheet !== 'undefined' && 'replaceSync' in CSSStyleSheet.prototype && 'adoptedStyleSheets' in root) {
    // constructed sheets: no <style> element, so a host's CSP needs no 'unsafe-inline' for them
    sheet ??= (() => {
      const s = new CSSStyleSheet()
      s.replaceSync(css)
      return s
    })()
    const own = sheet
    root.adoptedStyleSheets = [...root.adoptedStyleSheets.filter((s) => s !== own), own]
    if (!fonts && faces) {
      const f = new CSSStyleSheet()
      f.replaceSync(faces)
      document.adoptedStyleSheets = [...document.adoptedStyleSheets, f]
      fonts = true
    }
    return () => {
      root.adoptedStyleSheets = root.adoptedStyleSheets.filter((s) => s !== own)
    }
  }
  const el = document.createElement('style')
  el.textContent = css
  root.appendChild(el)
  return () => el.remove()
}

interface Live {
  theme: Theme
  path?: { to: string; n: number }
  locale: Locale
}

/** a host's locale, or the console's first */
const localeOf = (l?: string): Locale => (locales as readonly string[]).includes(l ?? '') ? (l as Locale) : locales[0]

function Embedded({ options, live, portal, element }: { options: TresorOptions; live: Live; portal: HTMLElement; element: HTMLElement }) {
  const navigate = useNavigate()
  const go = useRef(navigate) // useNavigate's function changes with the location: the host's path is applied once
  go.current = navigate
  const how = useNavigationType()
  const location = useLocation()
  const [state, setState] = useState<{ me?: Whoami; service?: ServiceInfo; notAdmin?: boolean; error?: string }>({})
  const [ended, setEnded] = useState(false) // the session refused even renewed, until a request passes again
  const [attempt, setAttempt] = useState(0) // Try again: the first load once more
  const alive = useRef(true) // unmounted: a request still on its way tells the host nothing
  useEffect(() => {
    alive.current = true
    return () => {
      alive.current = false
    }
  }, [])
  const api = useMemo(() => new Api(options.apiBase, (renew) => (renew ? options.getToken(options.audience, { renew }) : options.getToken(options.audience)), {
    unauthorized: () => {
      if (!alive.current) return
      setEnded(true)
      const now = Date.now()
      if (now - (told.get(element) ?? -Infinity) >= unauthorizedEvery) {
        told.set(element, now)
        options.onUnauthorized?.()
      }
    },
    authorized: () => {
      if (alive.current) setEnded(false)
    },
  }), [options, element])
  const base = trim(options.basePath ?? '')

  // the host navigated (its back button): follow, without telling it again
  useEffect(() => {
    if (live.path) go.current(inner(base, live.path.to), { replace: true, state: { fromHost: true } })
  }, [live.path, base])

  // the console navigated: the host's address bar and title follow
  useEffect(() => {
    const full = base + location.pathname + location.search
    if (!(location.state as { fromHost?: boolean } | null)?.fromHost) {
      const replace = how !== 'PUSH' // the first entry (POP) and a replace take the host's entry over
      if (options.onNavigate) options.onNavigate(full, { replace })
      else if (window.location.pathname + window.location.search !== full) window.history[replace ? 'replaceState' : 'pushState'](null, '', full)
    }
    const t = titles.find(([re]) => re.test(location.pathname))
    if (t) options.onTitle?.(t[1])
  }, [location, how, base, options])

  // the browser's back button when the console keeps the history itself
  useEffect(() => {
    if (options.onNavigate) return
    const back = () => go.current(inner(base, window.location.pathname + window.location.search), { replace: true, state: { fromHost: true } })
    window.addEventListener('popstate', back)
    return () => window.removeEventListener('popstate', back)
  }, [options, base])

  useEffect(() => {
    Promise.all([api.get<Whoami>('/v1/whoami'), api.get<ServiceInfo>('/admin/v1/service')]).then(
      ([me, service]) => setState({ me: me.data, service: service.data }),
      async (e) => {
        if (e instanceof ApiError && e.status === 403) {
          const me = await api.get<Whoami>('/v1/whoami').catch(() => undefined)
          setState({ me: me?.data, notAdmin: true })
        } else if (!(e instanceof ApiError && e.status === 401)) setState({ error: (e as Error).message }) // 401: the banner
      },
    )
  }, [api, attempt])

  const banner = ended && (
    <div role="alert" className="mb-3 flex items-center gap-3 rounded-md bg-warning-soft px-3.5 py-2.5 text-warning">
      <span>
        Your session ended: sign in again. What you were editing is kept.
        {!state.me && <span className="block text-[13px] opacity-80">If it stays, the host's token may lack tresor's audience.</span>}
      </span>
      <button type="button" className="btn border border-current bg-transparent py-1 text-current" onClick={() => setAttempt((n) => n + 1)}>
        Try again
      </button>
    </div>
  )
  if (state.error) return <div role="alert" className="rounded-md bg-danger-soft px-3.5 py-3 text-danger">{state.error}</div>
  if (state.notAdmin) {
    const roles = state.me?.roles ?? []
    return (
      <div role="alert" className="flex flex-col gap-1.5 rounded-md border border-line p-6">
        <strong className="text-[18px]">tresor is managed by administrators</strong>
        <span className="text-muted">
          None of your roles is one{roles.length ? <> (<span className="font-mono">{roles.join(', ')}</span>)</> : null}. What your roles are granted reaches you in DuckDB, not here.
        </span>
      </div>
    )
  }
  if (!state.me || !state.service) return banner || <div className="p-6 text-muted" aria-busy="true">Loading…</div>
  const config: ConsoleConfig = { api: options.apiBase, issuers: [], environment: state.service.environment }
  const app: AppState = { api, config, me: state.me, service: state.service, theme: live.theme, embedded: true, portal }
  return (
    <AppContext.Provider value={app}>
      <Toasts>
        {banner}
        <App />
      </Toasts>
    </AppContext.Provider>
  )
}

/** mounts the console in element's shadow root (made open when it has none) */
export function mountTresor(element: HTMLElement, options: TresorOptions): TresorHandle {
  if (!options?.apiBase || typeof options.getToken !== 'function') throw new Error('mountTresor: apiBase and getToken are required')
  if (mounted.has(element)) throw new Error('mountTresor: this element holds a console already (unmount it first)')
  mounted.add(element)
  const shadow = element.shadowRoot ?? element.attachShadow({ mode: 'open' })
  const unstyle = style(shadow)
  const frame = document.createElement('div')
  frame.className = 'mfe-root font-sans text-[14px] leading-[22px]'
  shadow.appendChild(frame)
  const portal = document.createElement('div')
  frame.appendChild(portal)
  const host = document.createElement('div')
  frame.appendChild(host)
  const root: Root = createRoot(host)
  const here = window.location.pathname + window.location.search
  const start = inner(options.basePath ?? '', here)
  const [pathname, search] = [start.split('?')[0], start.includes('?') ? start.slice(start.indexOf('?')) : '']
  // the host's own path as it is: nothing to tell it; its basePath alone (or another path) is told where the console is
  const fromHost = trim(options.basePath ?? '') + start === here
  let live: Live = { theme: options.theme ?? 'light', locale: localeOf(options.locale) }
  let n = 0
  let gone = false
  const render = () => {
    frame.dataset.theme = live.theme // Tailwind's dark: variants
    element.dataset.tresorTheme = live.theme // the variables' dark defaults, on :host
    root.render(
      <StrictMode>
        <MemoryRouter initialEntries={[{ pathname, search, state: { fromHost } }]} initialIndex={0}>
          <Embedded options={options} live={live} portal={portal} element={element} />
        </MemoryRouter>
      </StrictMode>,
    )
  }
  render()
  return {
    update({ theme, path, locale }) {
      if (gone) return
      live = { theme: theme ?? live.theme, path: path === undefined ? live.path : { to: path, n: ++n },
        locale: locale === undefined ? live.locale : localeOf(locale) }
      render()
    },
    unmount() {
      if (gone) return
      gone = true
      mounted.delete(element)
      root.unmount()
      frame.remove()
      delete element.dataset.tresorTheme
      unstyle()
    },
  }
}

/** <tresor-console api-base="…" base-path="…" theme="dark" audience="…" locale="en">: the token through the
 * getToken property (never an attribute), the host's callbacks as properties too (or the tresor-navigate,
 * tresor-title and tresor-unauthorized events); mounted when getToken is set; data-contract names the contract */
export class TresorConsole extends HTMLElement {
  static observedAttributes = ['theme', 'locale']
  private handle?: TresorHandle
  private tokenFn?: TresorOptions['getToken']
  declare onNavigate?: (path: string, how: { replace: boolean }) => void
  declare onTitle?: (title: string) => void
  declare onUnauthorized?: () => void

  constructor() {
    super()
    // properties a host set before this module defined the element: they would hide the class's own
    for (const key of ['getToken', 'onNavigate', 'onTitle', 'onUnauthorized'] as const) {
      if (Object.prototype.hasOwnProperty.call(this, key)) {
        const value = (this as Record<string, unknown>)[key]
        delete (this as Record<string, unknown>)[key]
        ;(this as Record<string, unknown>)[key] = value
      }
    }
  }

  set getToken(fn: TresorOptions['getToken'] | undefined) {
    this.tokenFn = typeof fn === 'function' ? fn : undefined
    if (this.tokenFn) this.mount()
    else this.disconnectedCallback() // no token function: nothing to call the service with
  }
  get getToken() {
    return this.tokenFn
  }

  connectedCallback() {
    this.dataset.contract = String(contract) // an attribute: set once connected, never in the constructor
    this.mount()
  }
  disconnectedCallback() {
    this.handle?.unmount()
    this.handle = undefined
  }
  attributeChangedCallback(name: string, _old: string | null, value: string | null) {
    if (name === 'theme' && (value === 'light' || value === 'dark')) this.handle?.update({ theme: value })
    if (name === 'locale' && value) this.handle?.update({ locale: value })
  }
  /** a path the host navigated to */
  navigate(path: string) {
    this.handle?.update({ path })
  }

  private mount() {
    if (this.handle || !this.isConnected || !this.tokenFn) return
    const theme = this.getAttribute('theme')
    this.handle = mountTresor(this, {
      apiBase: this.getAttribute('api-base') ?? '',
      basePath: this.getAttribute('base-path') ?? '',
      audience: this.getAttribute('audience') ?? undefined,
      theme: theme === 'dark' ? 'dark' : 'light',
      locale: this.getAttribute('locale') ?? undefined,
      getToken: (a, how) => this.tokenFn!(a, how),
      onUnauthorized: () => (this.onUnauthorized ? this.onUnauthorized() : this.dispatchEvent(new CustomEvent('tresor-unauthorized'))),
      onNavigate: (p, how) => (this.onNavigate ? this.onNavigate(p, how) : this.dispatchEvent(new CustomEvent('tresor-navigate', { detail: { path: p, ...how } }))),
      onTitle: (t) => (this.onTitle ? this.onTitle(t) : this.dispatchEvent(new CustomEvent('tresor-title', { detail: t }))),
    })
  }
}

if (typeof customElements !== 'undefined' && !customElements.get('tresor-console')) customElements.define('tresor-console', TresorConsole)
