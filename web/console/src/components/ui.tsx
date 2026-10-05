// The console's small parts: chips, states, search, pages, a row menu, toasts, the delete confirmation.
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { AlertTriangle, CheckCircle2, ChevronLeft, ChevronRight, CircleAlert, Lock, MoreHorizontal, Search } from 'lucide-react'
import type { Verb } from '../lib/types'
import { ApiError } from '../lib/api'
import { useApp } from '../context'

export function VerbChips({ verbs }: { verbs: Verb[] }) {
  return (
    <div className="flex flex-wrap gap-1">
      {verbs.map((v) => (
        <span key={v} className={`chip font-mono font-medium text-[11px] ${v === 'use' ? 'bg-success-soft text-success' : 'border border-line bg-soft text-ink'}`}>
          {v}
        </span>
      ))}
    </div>
  )
}

export function Masked({ label = 'write-only' }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-muted">
      <Lock size={15} aria-hidden />
      <span className="font-mono" aria-hidden>
        ••••••••
      </span>
      <span className="sr-only">{label}</span>
    </span>
  )
}

export function PageTitle({ eyebrow, title, children }: { eyebrow?: string; title: ReactNode; children?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end gap-4">
      <div className="flex flex-col gap-0.5">
        {eyebrow && <span className="eyebrow">{eyebrow}</span>}
        <h1 className="m-0 text-[24px] font-bold leading-8 tracking-[-0.01em]">{title}</h1>
      </div>
      {children}
    </div>
  )
}

export function SearchBox({ value, onChange, placeholder, label }: { value: string; onChange: (v: string) => void; placeholder: string; label: string }) {
  return (
    <label className="flex w-[300px] items-center gap-2 rounded-full border border-line px-3.5 py-1.5 text-muted">
      <Search size={15} aria-hidden />
      <span className="sr-only">{label}</span>
      <input type="search" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
        className="min-w-0 flex-1 border-0 bg-transparent text-[13px] text-ink outline-none" />
    </label>
  )
}

export function FilterChip({ on, onClick, children }: { on: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" aria-pressed={on} onClick={onClick}
      className={`rounded-full px-3.5 py-1.5 text-[13px] ${on ? 'border border-strong bg-strong font-semibold text-on-brand' : 'border border-line bg-surface text-ink'}`}>
      {children}
    </button>
  )
}

export function Pager({ page, pages, size, total, filtered, onPage, onSize }: {
  page: number; pages: number; size: number; total: number; filtered: number; onPage: (p: number) => void; onSize: (s: number) => void
}) {
  const from = filtered ? (page - 1) * size + 1 : 0
  const to = Math.min(page * size, filtered)
  return (
    <nav aria-label="Pages" className="flex items-center gap-3 text-[13px] text-muted">
      <label className="flex items-center gap-2">
        Rows per page
        <select value={size} onChange={(e) => onSize(Number(e.target.value))} className="input py-1 text-[13px]">
          {[10, 25, 50, 100].map((n) => <option key={n} value={n}>{n}</option>)}
        </select>
      </label>
      <span className="ml-auto">
        {filtered ? `${from}–${to} of ${filtered}` : 'Nothing matches'}
        {filtered < total ? ` (filtered from ${total})` : ''}
      </span>
      <button type="button" className="icon-btn border border-line" aria-label="Previous page" disabled={page <= 1} onClick={() => onPage(page - 1)}>
        <ChevronLeft size={16} />
      </button>
      <span className="text-ink">Page {page} of {pages}</span>
      <button type="button" className="icon-btn border border-line" aria-label="Next page" disabled={page >= pages} onClick={() => onPage(page + 1)}>
        <ChevronRight size={16} />
      </button>
    </nav>
  )
}

export function usePaging<T>(items: T[], initial = 25) {
  const [page, setPage] = useState(1)
  const [size, setSize] = useState(initial)
  const pages = Math.max(1, Math.ceil(items.length / size))
  const current = Math.min(page, pages)
  return {
    rows: items.slice((current - 1) * size, current * size),
    pager: { page: current, pages, size, filtered: items.length, onPage: setPage, onSize: (s: number) => { setSize(s); setPage(1) } },
    reset: () => setPage(1),
  }
}

export function Skeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-3.5 p-4" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex gap-4">
          <div className="h-3.5 w-1/4 rounded-full bg-soft" />
          <div className="h-3.5 w-1/6 rounded-full bg-soft" />
          <div className="h-3.5 w-1/3 rounded-full bg-soft" />
        </div>
      ))}
    </div>
  )
}

/** what an answer that failed says to a person */
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const e = error instanceof ApiError ? error : undefined
  const title =
    e?.type === 'no_verb' ? 'Not allowed' : e?.status === 404 ? 'Not found' : e?.type === 'service_unavailable' ? 'The service did not answer' : 'Something went wrong'
  return (
    <div role="alert" className="flex items-start gap-3 rounded-md bg-danger-soft p-4 text-danger">
      <CircleAlert size={18} className="mt-0.5 flex-none" aria-hidden />
      <div className="flex flex-1 flex-col gap-1">
        <strong>{title}</strong>
        <span>{e ? e.message : String(error)}</span>
      </div>
      {onRetry && <button type="button" className="btn border border-current bg-transparent text-current" onClick={onRetry}>Retry</button>}
    </div>
  )
}

export function Empty({ icon, title, children }: { icon: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-3 rounded-lg border border-line p-8">
      <span className="text-brand">{icon}</span>
      <strong className="text-[16px]">{title}</strong>
      {children}
    </div>
  )
}

export function Banner({ tone, children }: { tone: 'warning' | 'danger' | 'success' | 'info'; children: ReactNode }) {
  const cls = { warning: 'bg-warning-soft text-warning', danger: 'bg-danger-soft text-danger', success: 'bg-success-soft text-success', info: 'bg-soft text-muted' }[tone]
  const Icon = tone === 'success' ? CheckCircle2 : tone === 'info' ? Lock : AlertTriangle
  return (
    <div role={tone === 'info' ? 'note' : 'alert'} className={`flex items-start gap-2.5 rounded-md px-4 py-3 text-[13px] ${cls}`}>
      <Icon size={16} className="mt-[3px] flex-none" aria-hidden />
      <div className="flex-1">{children}</div>
    </div>
  )
}

/** a row's actions: a small menu, drawn over the page (a table's scrolling box would clip it), below the button
 * or above it when there is no room; closed on a click elsewhere, Escape, a scroll or a resize */
export function RowMenu({ label, items }: { label: string; items: { label: string; danger?: boolean; onSelect: () => void }[] }) {
  const [at, setAt] = useState<{ top: number; right: number; up: boolean } | null>(null)
  const { portal } = useApp()
  const button = useRef<HTMLButtonElement>(null)
  const menu = useRef<HTMLDivElement>(null)
  const open = at !== null
  useEffect(() => {
    if (!open) return
    const close = (e: Event) => {
      const target = e.composedPath()[0] as Node // inside a shadow root, e.target is its host
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : e.type !== 'mousedown' || (!menu.current?.contains(target) && !button.current?.contains(target))) {
        setAt(null)
        if (e instanceof KeyboardEvent) button.current?.focus()
      }
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', close)
    window.addEventListener('scroll', close, true)
    // a scroll inside a shadow root does not reach the window (the microfrontend)
    const shadow = button.current?.getRootNode()
    const inner = shadow instanceof ShadowRoot ? shadow : undefined
    inner?.addEventListener('scroll', close, true)
    window.addEventListener('resize', close)
    menu.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus()
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', close)
      window.removeEventListener('scroll', close, true)
      inner?.removeEventListener('scroll', close, true)
      window.removeEventListener('resize', close)
    }
  }, [open])
  const toggle = () => {
    if (open) return setAt(null)
    const r = button.current!.getBoundingClientRect()
    const height = 8 + items.length * 40
    const up = r.bottom + height > window.innerHeight && r.top > height
    setAt({ top: up ? r.top - height - 4 : r.bottom + 4, right: window.innerWidth - r.right, up })
  }
  return (
    <>
      <button ref={button} type="button" className="icon-btn" aria-label={`Actions for ${label}`} aria-haspopup="menu" aria-expanded={open} onClick={toggle}>
        <MoreHorizontal size={18} />
      </button>
      {at &&
        createPortal(
          <div ref={menu} role="menu" aria-label={label} style={{ position: 'fixed', top: at.top, right: at.right }}
            className="z-50 flex min-w-[168px] flex-col rounded-md border border-line bg-surface p-1.5 text-left text-ink"
            onKeyDown={(e) => {
              const all = [...(menu.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? [])]
              const i = all.indexOf((menu.current?.getRootNode() as Document | ShadowRoot | undefined)?.activeElement as HTMLElement)
              if (e.key === 'ArrowDown') { e.preventDefault(); all[(i + 1) % all.length]?.focus() }
              if (e.key === 'ArrowUp') { e.preventDefault(); all[(i - 1 + all.length) % all.length]?.focus() }
            }}>
            {items.map((it) => (
              <button key={it.label} type="button" role="menuitem" onClick={() => { setAt(null); it.onSelect() }}
                className={`rounded-[10px] px-3 py-2 text-left hover:bg-soft focus:bg-soft ${it.danger ? 'text-danger' : 'text-ink'}`}>
                {it.label}
              </button>
            ))}
          </div>,
          portal ?? document.body,
        )}
    </>
  )
}

/** deleting: the name typed to confirm, in a native modal dialog (its own focus trap and Escape) */
export function ConfirmDelete({ kind, name, consequence, onConfirm, onClose }: {
  kind: string; name: string | null; consequence: string; onConfirm: () => Promise<void>; onClose: () => void
}) {
  const dialog = useRef<HTMLDialogElement>(null)
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  useEffect(() => {
    if (name) {
      setTyped('')
      setError(null)
      dialog.current?.showModal()
    } else dialog.current?.close()
  }, [name])
  return (
    <dialog ref={dialog} onClose={onClose} aria-labelledby="delete-title"
      className="w-[520px] max-w-full rounded-lg border border-line bg-surface p-7 text-ink">
      <div className="flex flex-col gap-3.5">
        <strong id="delete-title" className="text-[18px]">Delete the {kind} <span className="font-mono">{name}</span>?</strong>
        <span className="text-muted">{consequence} Its grants go with it. This cannot be undone.</span>
        <label className="flex flex-col gap-1.5 text-[13px] font-semibold">
          Type the name to confirm
          <input className="input font-mono" value={typed} onChange={(e) => setTyped(e.target.value)} autoFocus />
        </label>
        {error != null && <ErrorState error={error} />}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-secondary" onClick={onClose}>Cancel</button>
          <button type="button" className="btn-danger-fill" disabled={typed !== name || busy}
            onClick={async () => {
              setBusy(true)
              try {
                await onConfirm()
              } catch (e) {
                setError(e)
              } finally {
                setBusy(false)
              }
            }}>
            Delete
          </button>
        </div>
      </div>
    </dialog>
  )
}

// --- toasts ---------------------------------------------------------------------------------------------

const ToastContext = createContext<(text: string) => void>(() => {})

export function Toasts({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<{ id: number; text: string }[]>([])
  const push = useCallback((text: string) => {
    const id = Date.now() + Math.random()
    setItems((xs) => [...xs, { id, text }])
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), 4000)
  }, [])
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div aria-live="polite" className="fixed bottom-6 right-6 z-50 flex flex-col items-end gap-2">
        {items.map((t) => (
          <div key={t.id} role="status" className="inline-flex items-center gap-2.5 rounded-full bg-ink px-4 py-2.5 text-surface">
            <CheckCircle2 size={16} aria-hidden />
            {t.text}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export const useToast = () => useContext(ToastContext)
