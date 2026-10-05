// The standalone console (spec 010): /ui/config.json, sign-in, then the console for administrators.
import { StrictMode, useEffect, useMemo, useState, useSyncExternalStore } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, useNavigate } from 'react-router-dom'
import './styles.css'
import { App } from './App'
import { AppContext, type AppState, type Theme } from './context'
import { Api, ApiError } from './lib/api'
import { Session, SessionEnded } from './lib/auth'
import { loadConfig, type ConsoleConfig } from './lib/config'
import type { ServiceInfo, Whoami } from './lib/types'
import { Toasts } from './components/ui'
import { Loading, NotAdmin, SignIn } from './screens/Entry'

const basename = new URL(document.baseURI).pathname.replace(/\/$/, '')

function initialTheme(): Theme {
  try {
    const t = localStorage.getItem('tresor.theme') // a viewer's convenience, nothing more
    if (t === 'light' || t === 'dark') return t
  } catch {
    /* storage refused: the system's */
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function Console({ config, session }: { config: ConsoleConfig; session: Session }) {
  const navigate = useNavigate()
  const signedIn = useSyncExternalStore((l) => session.subscribe(l), () => session.signedIn)
  const [theme, setTheme] = useState<Theme>(initialTheme)
  const [state, setState] = useState<{ me?: Whoami; service?: ServiceInfo; notAdmin?: boolean; error?: string }>({})
  const [phase, setPhase] = useState<'start' | 'callback' | 'ready'>(window.location.pathname === `${basename}/callback` ? 'callback' : 'start')
  const api = useMemo(() => new Api(config.api, () => session.token()), [config, session])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem('tresor.theme', theme)
    } catch {
      /* not kept */
    }
  }, [theme])

  // the redirect's return: the code exchanged, back to where the sign-in began
  useEffect(() => {
    if (phase !== 'callback') return
    session.callback().then(
      (to) => {
        if (to === undefined) window.close()
        else {
          setPhase('ready')
          navigate(to, { replace: true })
        }
      },
      (e) => {
        setState({ error: `The sign-in did not complete: ${(e as Error).message}` })
        setPhase('ready')
        navigate('/', { replace: true })
      },
    )
  }, [phase, session, navigate])

  // no session: the issuer used last in this tab signs in again on its own (no prompt with an IdP session)
  useEffect(() => {
    if (phase !== 'start') return
    const last = session.remembered()
    if (!session.signedIn && last && !state.error) {
      session.signIn(last, window.location.pathname.slice(basename.length) || '/secrets').catch((e) => setState({ error: (e as Error).message }))
    } else setPhase('ready')
  }, [phase, session, state.error])

  // signed in: who, and whether an administrator (the console's API answers 403 otherwise)
  useEffect(() => {
    if (!signedIn || state.me) return
    Promise.all([api.get<Whoami>('/v1/whoami'), api.get<ServiceInfo>('/admin/v1/service')]).then(
      ([me, service]) => setState({ me: me.data, service: service.data }),
      async (e) => {
        if (e instanceof ApiError && e.status === 403) {
          const me = await api.get<Whoami>('/v1/whoami').catch(() => undefined)
          setState({ me: me?.data, notAdmin: true })
        } else if (!(e instanceof SessionEnded)) setState({ error: (e as Error).message })
      },
    )
  }, [signedIn, api, state.me])

  const signOut = () => {
    session.signOut().then(() => {
      setState({})
      navigate('/', { replace: true })
    })
  }
  if (phase !== 'ready') return <Loading />
  if (!signedIn && !state.me) return <SignIn config={config} session={session} theme={theme} error={state.error} />
  if (state.notAdmin) return <NotAdmin roles={state.me?.roles ?? []} onSignOut={signOut} theme={theme} />
  if (!state.me || !state.service) return state.error ? <SignIn config={config} session={session} theme={theme} error={state.error} /> : <Loading />
  const app: AppState = { api, config, me: state.me, service: state.service, theme, setTheme, signOut, embedded: false, displayName: session.displayName }
  return (
    <AppContext.Provider value={app}>
      <Toasts>
        {!signedIn && <SessionBanner session={session} />}
        <App />
      </Toasts>
    </AppContext.Provider>
  )
}

/** the session ended: sign in again in a popup, keeping the page and an editor's input */
function SessionBanner({ session }: { session: Session }) {
  const [error, setError] = useState('')
  return (
    <div role="alert" className="fixed inset-x-0 top-0 z-50 flex items-center justify-center gap-3 bg-warning-soft px-4 py-2.5 text-warning">
      Your session ended. Your edit is kept.
      <button type="button" className="btn border border-current bg-transparent py-1 text-current" onClick={() => session.renew().catch((e) => setError((e as Error).message))}>
        Sign in again
      </button>
      {error && <span className="text-danger">{error}</span>}
    </div>
  )
}

loadConfig().then(
  (config) => {
    const session = new Session(config.issuers)
    createRoot(document.getElementById('root')!).render(
      <StrictMode>
        <BrowserRouter basename={basename}>
          <Console config={config} session={session} />
        </BrowserRouter>
      </StrictMode>,
    )
  },
  (e) => {
    document.getElementById('root')!.textContent = `The console could not start: ${(e as Error).message}`
  },
)
