// The console as a microfrontend (spec 010, c): mountTresor(element, options) and <tresor-console>. The host owns
// sign-in, navigation and the theme; the console renders in the element's shadow root, its styles its own.
import { StrictMode, useEffect, useMemo, useState } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { MemoryRouter, useLocation, useNavigate } from 'react-router-dom'
import css from './styles.css?inline'
import { App } from './App'
import { AppContext, type AppState, type Theme } from './context'
import { Api, ApiError } from './lib/api'
import type { ConsoleConfig } from './lib/config'
import type { ServiceInfo, Whoami } from './lib/types'
import { Toasts } from './components/ui'

export interface TresorOptions {
  /** the service's URL (its public_url): /v1 and /admin/v1 are below it */
  apiBase: string
  /** an access token carrying tresor's audience; called before each request, so the host renews it */
  getToken: (audience?: string) => Promise<string>
  /** the audience the host asks for, when its tokens do not carry tresor's already */
  audience?: string
  theme?: Theme
  /** the host's path the console lives under, e.g. /platform/tresor; the console's own paths follow it */
  basePath?: string
  /** the console moved: the host's full path, for its address bar and history. Without it the console pushes
   * the browser's history itself */
  onNavigate?: (path: string) => void
  /** the section shown, for the host's title or breadcrumbs */
  onTitle?: (title: string) => void
}

export interface TresorHandle {
  /** a new theme, or a path the host navigated to (its back button) */
  update(options: { theme?: Theme; path?: string }): void
  unmount(): void
}

const titles: [RegExp, string][] = [
  [/^\/secrets/, 'Secrets'], [/^\/create\/secret/, 'New secret'], [/^\/variables/, 'Variables'], [/^\/create\/variable/, 'New variable'],
  [/^\/access/, 'Access'], [/^\/refs/, 'References check'], [/^\/service/, 'Service'],
]

const trim = (p: string) => p.replace(/\/+$/, '')

/** the console's own path from the host's: below basePath, else the start */
function inner(basePath: string, path: string): string {
  const base = trim(basePath)
  if (base && path !== base && !path.startsWith(base + '/')) return '/secrets'
  return path.slice(base.length) || '/secrets'
}

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
}

function Embedded({ options, live, portal }: { options: TresorOptions; live: Live; portal: HTMLElement }) {
  const navigate = useNavigate()
  const location = useLocation()
  const [state, setState] = useState<{ me?: Whoami; service?: ServiceInfo; notAdmin?: boolean; error?: string }>({})
  const api = useMemo(() => new Api(options.apiBase, () => options.getToken(options.audience)), [options])
  const base = trim(options.basePath ?? '')

  // the host navigated (its back button): follow, without telling it again
  useEffect(() => {
    if (live.path) navigate(inner(base, live.path.to), { replace: true, state: { fromHost: true } })
  }, [live.path, base, navigate])

  // the console navigated: the host's address bar and title follow
  useEffect(() => {
    const full = base + location.pathname
    if (!(location.state as { fromHost?: boolean } | null)?.fromHost) {
      if (options.onNavigate) options.onNavigate(full)
      else if (window.location.pathname !== full) window.history.pushState(null, '', full)
    }
    const t = titles.find(([re]) => re.test(location.pathname))
    if (t) options.onTitle?.(t[1])
  }, [location, base, options])

  // the browser's back button when the console keeps the history itself
  useEffect(() => {
    if (options.onNavigate) return
    const back = () => navigate(inner(base, window.location.pathname), { replace: true, state: { fromHost: true } })
    window.addEventListener('popstate', back)
    return () => window.removeEventListener('popstate', back)
  }, [options, base, navigate])

  useEffect(() => {
    Promise.all([api.get<Whoami>('/v1/whoami'), api.get<ServiceInfo>('/admin/v1/service')]).then(
      ([me, service]) => setState({ me: me.data, service: service.data }),
      async (e) => {
        if (e instanceof ApiError && e.status === 403) {
          const me = await api.get<Whoami>('/v1/whoami').catch(() => undefined)
          setState({ me: me?.data, notAdmin: true })
        } else setState({ error: e instanceof ApiError && e.status === 401 ? "The host's token was refused: it needs tresor's audience." : (e as Error).message })
      },
    )
  }, [api])

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
  if (!state.me || !state.service) return <div className="p-6 text-muted" aria-busy="true">Loading…</div>
  const config: ConsoleConfig = { api: options.apiBase, issuers: [], environment: state.service.environment }
  const app: AppState = { api, config, me: state.me, service: state.service, theme: live.theme, embedded: true, portal }
  return (
    <AppContext.Provider value={app}>
      <Toasts>
        <App />
      </Toasts>
    </AppContext.Provider>
  )
}

/** mounts the console in element's shadow root (made open when it has none) */
export function mountTresor(element: HTMLElement, options: TresorOptions): TresorHandle {
  if (!options?.apiBase || typeof options.getToken !== 'function') throw new Error('mountTresor: apiBase and getToken are required')
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
  const start = inner(options.basePath ?? '', window.location.pathname)
  let live: Live = { theme: options.theme ?? 'light' }
  let n = 0
  const render = () => {
    frame.dataset.theme = live.theme
    root.render(
      <StrictMode>
        <MemoryRouter initialEntries={[{ pathname: start, state: { fromHost: true } }]}>
          <Embedded options={options} live={live} portal={portal} />
        </MemoryRouter>
      </StrictMode>,
    )
  }
  render()
  return {
    update({ theme, path }) {
      live = { theme: theme ?? live.theme, path: path === undefined ? live.path : { to: path, n: ++n } }
      render()
    },
    unmount() {
      root.unmount()
      frame.remove()
      unstyle()
    },
  }
}

/** <tresor-console api-base="…" base-path="…" theme="dark" audience="…">: the token through the getToken
 * property (never an attribute), the host's callbacks as properties too; mounted when getToken is set */
export class TresorConsole extends HTMLElement {
  static observedAttributes = ['theme']
  private handle?: TresorHandle
  private tokenFn?: TresorOptions['getToken']
  onNavigate?: (path: string) => void
  onTitle?: (title: string) => void

  set getToken(fn: TresorOptions['getToken'] | undefined) {
    this.tokenFn = fn
    this.mount()
  }
  get getToken() {
    return this.tokenFn
  }

  connectedCallback() {
    this.mount()
  }
  disconnectedCallback() {
    this.handle?.unmount()
    this.handle = undefined
  }
  attributeChangedCallback(name: string, _old: string | null, value: string | null) {
    if (name === 'theme' && (value === 'light' || value === 'dark')) this.handle?.update({ theme: value })
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
      getToken: (a) => this.tokenFn!(a),
      onNavigate: (p) => (this.onNavigate ? this.onNavigate(p) : this.dispatchEvent(new CustomEvent('tresor-navigate', { detail: p }))),
      onTitle: (t) => (this.onTitle ? this.onTitle(t) : this.dispatchEvent(new CustomEvent('tresor-title', { detail: t }))),
    })
  }
}

if (typeof customElements !== 'undefined' && !customElements.get('tresor-console')) customElements.define('tresor-console', TresorConsole)
