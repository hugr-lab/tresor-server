// Who may use an entry: grants give `use` to a role or a group, never a person (specs/009); each change is one
// write, at once.
import { useState } from 'react'
import { Users, X } from 'lucide-react'
import { useApp, useLoad } from '../context'
import { seg } from '../lib/api'
import type { Grant } from '../lib/types'
import { ErrorState } from './ui'

const grantID = (principal: string) => principal.replace(/[^A-Za-z0-9_.-]/g, '-')

export function Grants({ kind, name, onChange }: { kind: 'secrets' | 'variables'; name: string; onChange?: () => void }) {
  const { api } = useApp()
  const grants = useLoad(() => api.get<Grant[]>(`/v1/${kind}/${seg(name)}/grants`).then((r) => r.data), [api, kind, name])
  const [principal, setPrincipal] = useState('')
  const [error, setError] = useState<unknown>(null)
  const valid = /^(role|group):\S+$/.test(principal.trim())
  const change = async (f: () => Promise<unknown>) => {
    setError(null)
    try {
      await f()
      grants.reload()
      onChange?.()
    } catch (e) {
      setError(e)
    }
  }
  return (
    <section aria-label="Grants" className="flex flex-col gap-3.5 rounded-lg border border-line p-5">
      <div className="flex items-center gap-2">
        <Users size={18} className="text-brand" aria-hidden />
        <h2 className="m-0 text-[16px] font-bold">Who may use it</h2>
      </div>
      <span className="text-[13px] text-muted">A grant gives <span className="font-mono">use</span> to a role or a group. Being an administrator gives none.</span>
      {grants.error != null && <ErrorState error={grants.error} onRetry={grants.reload} />}
      <ul className="m-0 flex list-none flex-col gap-2 p-0">
        {(grants.data ?? []).map((g) => (
          <li key={g.id} className="flex items-center gap-2 rounded-full bg-soft py-1.5 pl-3.5 pr-1.5">
            <span className="font-mono text-[13px]">{g.principal}</span>
            <span className="chip bg-success-soft font-mono text-[11px] font-medium text-success">use</span>
            <button type="button" className="icon-btn ml-auto h-7 w-7" aria-label={`Revoke ${g.principal}`}
              onClick={() => change(() => api.call('DELETE', `/v1/${kind}/${seg(name)}/grants/${seg(g.id)}`))}>
              <X size={15} />
            </button>
          </li>
        ))}
        {grants.data?.length === 0 && <li className="text-[13px] text-muted">No one: nobody's DuckDB receives it.</li>}
      </ul>
      <form className="flex gap-2" onSubmit={(e) => {
        e.preventDefault()
        if (!valid) return
        const p = principal.trim()
        change(() => api.call('PUT', `/v1/${kind}/${seg(name)}/grants/${seg(grantID(p))}`, { principal: p, verbs: ['use'] })).then(() => setPrincipal(''))
      }}>
        <label className="flex flex-1 items-center rounded-sm border border-line px-3 py-1.5">
          <span className="sr-only">Principal</span>
          <input value={principal} onChange={(e) => setPrincipal(e.target.value)} placeholder="role:… or group:…"
            className="min-w-0 flex-1 border-0 bg-transparent font-mono text-[13px] text-ink outline-none" />
        </label>
        <button type="submit" className="btn-secondary" disabled={!valid}>Grant</button>
      </form>
      {error != null && <ErrorState error={error} />}
    </section>
  )
}
