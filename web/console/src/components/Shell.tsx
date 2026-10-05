// The standalone console's frame: the sidebar (the same on every screen), the top bar (the environment badge,
// the theme, the user). In a host's shell (the microfrontend) the console shows its own section tabs instead.
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { NavLink } from 'react-router-dom'
import { ChevronDown, KeyRound, LogOut, Moon, ServerCog, ShieldCheck, Sun, Users, Variable } from 'lucide-react'
import { useApp } from '../context'
import { useToast } from './ui'
import iconOnDark from '../assets/hugr-icon-on-dark.svg'

const items = [
  { to: '/secrets', label: 'Secrets', icon: KeyRound, count: 'secrets' as const },
  { to: '/variables', label: 'Variables', icon: Variable, count: 'variables' as const },
]
const admin = [
  { to: '/access', label: 'Access', icon: Users },
  { to: '/refs', label: 'References check', icon: ShieldCheck },
  { to: '/service', label: 'Service', icon: ServerCog },
]

export function Shell({ counts, children }: { counts: { secrets?: number; variables?: number }; children: ReactNode }) {
  const { embedded } = useApp()
  if (embedded) return <EmbeddedFrame>{children}</EmbeddedFrame>
  return (
    <div className="app flex">
      <Sidebar counts={counts} />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="flex w-full max-w-[1360px] flex-col gap-5 px-8 pb-10 pt-7">{children}</main>
      </div>
    </div>
  )
}

function Sidebar({ counts }: { counts: { secrets?: number; variables?: number } }) {
  const { service } = useApp()
  const link = ({ isActive }: { isActive: boolean }) =>
    `flex items-center gap-2.5 rounded-full px-3 py-2 no-underline ${isActive ? 'bg-[#1E4A60] font-semibold text-white' : 'text-[#C9DCE0] hover:text-white'}`
  return (
    <nav aria-label="Main" className="flex w-[232px] flex-none flex-col gap-1 bg-[#0A3146] px-3.5 py-5 text-[#E8F1F2]">
      <div className="flex items-center gap-2.5 px-2 pb-5">
        <img src={iconOnDark} alt="hugr" width={28} height={28} />
        <div className="flex flex-col leading-[18px]">
          <span className="text-[17px] font-bold text-white">tresor</span>
          <span className="text-[12px] text-[#9CB1BA]">secrets for DuckDB</span>
        </div>
      </div>
      {items.map((it) => (
        <NavLink key={it.to} to={it.to} className={link}>
          <it.icon size={18} aria-hidden />
          {it.label}
          {counts[it.count] !== undefined && <span className="ml-auto text-[12px] text-[#9CB1BA]">{counts[it.count]}</span>}
        </NavLink>
      ))}
      <div className="mx-3 mb-1.5 mt-[18px] text-[12px] font-semibold uppercase tracking-[0.08em] text-[#9CB1BA]">Administration</div>
      {admin.map((it) => (
        <NavLink key={it.to} to={it.to} className={link}>
          <it.icon size={18} aria-hidden />
          {it.label}
        </NavLink>
      ))}
      <div className="mt-auto flex flex-col gap-1 rounded-md bg-[#061C28] p-3">
        <span className="text-[12px] text-[#9CB1BA]">Service</span>
        <span className="truncate font-mono text-[12px]">{new URL(useApp().config.api).host}</span>
        <span className={`text-[12px] ${service.ready.ready ? 'text-[#5FCB91]' : 'text-[#E8B45C]'}`}>
          ● {service.ready.ready ? 'Ready' : 'Not ready'} · {service.version}
        </span>
      </div>
    </nav>
  )
}

function TopBar() {
  const { config, theme, setTheme } = useApp()
  return (
    <header className="flex items-center gap-3 border-b border-line px-8 py-3.5">
      {config.environment && (
        <span className="rounded-full bg-warning-soft px-2.5 py-0.5 text-[12px] font-bold uppercase tracking-[0.06em] text-warning">
          {config.environment}
        </span>
      )}
      <div className="ml-auto flex items-center gap-2">
        {setTheme && (
          <button type="button" className="icon-btn h-9 w-9 border border-line text-ink" aria-label={theme === 'dark' ? 'Light theme' : 'Dark theme'}
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
            {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
          </button>
        )}
        <UserMenu />
      </div>
    </header>
  )
}

function UserMenu() {
  const { me, api, signOut, displayName } = useApp()
  const toast = useToast()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !ref.current?.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', close)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', close)
    }
  }, [open])
  const full = displayName || me.subject
  const name = full.length > 24 ? full.slice(0, 22) + '…' : full
  return (
    <div className="relative" ref={ref}>
      <button type="button" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)}
        className="flex items-center gap-2.5 rounded-full border border-line bg-surface py-1 pl-1 pr-3 text-ink">
        <span className="flex h-7 w-7 items-center justify-center rounded-full bg-strong text-[12px] font-bold text-on-brand">
          {full.split(/[\s._@-]+/).filter(Boolean).slice(0, 2).map((w) => w[0]).join('').toUpperCase()}
        </span>
        <span className="flex flex-col items-start leading-4">
          <span className="text-[13px] font-semibold">{name}</span>
          <span className="text-[12px] font-semibold text-strong">Administrator</span>
        </span>
        <ChevronDown size={16} aria-hidden />
      </button>
      {open && (
        <div role="menu" className="absolute right-0 top-12 z-30 flex w-[320px] flex-col gap-3 rounded-md border border-line bg-surface p-4">
          <div className="flex flex-col gap-0.5">
            <span className="eyebrow">Signed in</span>
            <span className="break-all font-mono text-[12px]">{me.subject}</span>
            <span className="break-all text-[12px] text-muted">{me.issuer}</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {me.roles.map((r) => <span key={r} className="chip border border-line font-mono font-normal">{r}</span>)}
          </div>
          <span className="text-[12px] text-muted">The session ends {new Date(me.expires_at).toLocaleTimeString()}.</span>
          <button type="button" role="menuitem" className="btn-ghost justify-start px-2" onClick={async () => {
            try {
              const r = await api.call<{ revoked: number }>('DELETE', '/v1/delegations')
              toast(`${r.data.revoked} session(s) on servers revoked`)
            } catch (e) {
              toast(`Not revoked: ${(e as Error).message}`)
            }
            setOpen(false)
          }}>
            Revoke my sessions on servers
          </button>
          {signOut && (
            <button type="button" role="menuitem" className="btn-ghost justify-start px-2" onClick={signOut}>
              <LogOut size={16} aria-hidden /> Sign out
            </button>
          )}
        </div>
      )}
    </div>
  )
}

function EmbeddedFrame({ children }: { children: ReactNode }) {
  const tab = ({ isActive }: { isActive: boolean }) =>
    `rounded-full px-4 py-1.5 no-underline ${isActive ? 'bg-strong font-semibold text-on-brand' : 'border border-line text-ink'}`
  return (
    <div className="mfe flex flex-col gap-4">
      <nav aria-label="tresor" className="flex flex-wrap gap-1.5">
        {[...items, ...admin].map((it) => <NavLink key={it.to} to={it.to} className={tab}>{it.label}</NavLink>)}
      </nav>
      {children}
    </div>
  )
}
