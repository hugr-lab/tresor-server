// Before the console: signing in, the redirect's return, and a refusal for whoever is not an administrator.
import { useState } from 'react'
import { CircleAlert, LogIn } from 'lucide-react'
import type { ConsoleConfig } from '../lib/config'
import type { Session } from '../lib/auth'
import logo from '../assets/hugr-logo.svg'
import logoOnDark from '../assets/hugr-logo-on-dark.svg'

function Card({ children, theme }: { children: React.ReactNode; theme: string }) {
  return (
    <div className="app flex items-center justify-center bg-surface p-8">
      <div className="flex w-full max-w-[440px] flex-col gap-6 rounded-lg border border-line bg-surface p-10">
        <img src={theme === 'dark' ? logoOnDark : logo} alt="hugr" width={120} />
        {children}
      </div>
    </div>
  )
}

export function SignIn({ config, session, theme, error: given }: { config: ConsoleConfig; session: Session; theme: string; error?: string }) {
  const host = new URL(config.api).host
  const [failed, setFailed] = useState<string>()
  const error = failed ?? given
  return (
    <Card theme={theme}>
      <div className="flex flex-col gap-1.5">
        <span className="eyebrow">tresor console</span>
        <h1 className="m-0 text-[26px] font-bold leading-[34px] tracking-[-0.01em]">Sign in to manage secrets</h1>
        <span className="font-mono text-[13px] text-muted">{host}</span>
      </div>
      {error && <div role="alert" className="flex gap-2.5 rounded-md bg-danger-soft px-3.5 py-3 text-danger"><CircleAlert size={18} className="mt-0.5 flex-none" aria-hidden />{error}</div>}
      {config.issuers.length === 0 ? (
        <span className="text-muted">No identity provider has a public client (<span className="font-mono">client_id</span>) in this service's configuration: no one can sign in here.</span>
      ) : (
        <div className="flex flex-col gap-2.5">
          {config.issuers.map((is, i) => (
            <button key={is.issuer} type="button" className={i === 0 ? 'btn-primary justify-center py-3' : 'btn-secondary justify-center py-3'}
              onClick={() => session.signIn(is, window.location.pathname.replace(new URL(document.baseURI).pathname.replace(/\/$/, ''), '') || '/secrets')
                .catch((e) => setFailed(`The identity provider did not answer: ${(e as Error).message}`))}>
              <LogIn size={18} aria-hidden /> Sign in with {new URL(is.issuer).host}
            </button>
          ))}
        </div>
      )}
      <span className="text-[13px] text-muted">The console is for administrators. Day to day, manage secrets from DuckDB with <span className="font-mono">CREATE PERSISTENT SECRET … IN tresor</span>.</span>
    </Card>
  )
}

export function NotAdmin({ roles, onSignOut, theme }: { roles: string[]; onSignOut: () => void; theme: string }) {
  return (
    <Card theme={theme}>
      <div role="alert" className="flex flex-col gap-2">
        <h1 className="m-0 text-[22px] font-bold">The console is for administrators</h1>
        <span className="text-muted">
          None of your roles is one{roles.length ? <> (<span className="font-mono">{roles.join(', ')}</span>)</> : null}. What your roles are granted reaches you in DuckDB, not here.
        </span>
      </div>
      <button type="button" className="btn-secondary self-start" onClick={onSignOut}>Sign out</button>
    </Card>
  )
}

export function Loading() {
  return <div className="app flex items-center justify-center text-muted" aria-busy="true">Loading…</div>
}
