// What every screen reaches: the API with the session's token, the configuration, who is signed in, the service,
// the theme. In the microfrontend the host gives the token and the theme (spec 010, PR c).
import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import type { Api } from './lib/api'
import type { ConsoleConfig } from './lib/config'
import type { ServiceInfo, Whoami } from './lib/types'

export type Theme = 'light' | 'dark'

export interface AppState {
  api: Api
  config: ConsoleConfig
  me: Whoami
  displayName?: string // the person's name, from the sign-in (the console's own; not a principal)
  service: ServiceInfo
  theme: Theme
  setTheme?: (t: Theme) => void // the standalone console's own switch; a host owns it otherwise
  signOut?: () => void
  embedded: boolean // mounted in a host's shell: no sidebar, no top bar
  portal?: HTMLElement // where a menu over the page is drawn: inside the shadow root when mounted (its styles)
}

export const AppContext = createContext<AppState | null>(null)

export function useApp(): AppState {
  const s = useContext(AppContext)
  if (!s) throw new Error('outside the console')
  return s
}

/** a value loaded from the API: the data, the error, and a reload */
export function useLoad<T>(load: () => Promise<T>, deps: unknown[]) {
  const [state, setState] = useState<{ data?: T; error?: unknown; loading: boolean }>({ loading: true })
  const [n, setN] = useState(0)
  useEffect(() => {
    let live = true
    setState((s) => ({ ...s, loading: true, error: undefined }))
    load().then(
      (data) => live && setState({ data, loading: false }),
      (error) => live && setState({ error, loading: false }),
    )
    return () => {
      live = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, n])
  return { ...state, reload: useCallback(() => setN((x) => x + 1), []) }
}
