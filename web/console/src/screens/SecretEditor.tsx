// Creating a secret (PUT, If-None-Match: *) and replacing one (the console's merge, If-Match): a replace keeps
// what the administrator never saw - every parameter is kept, set anew, or removed - and a kept secret parameter
// stays secret.
import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Lock, Plus, Terminal, Trash2, X } from 'lucide-react'
import { useApp, useLoad } from '../context'
import { useLists } from '../lists'
import { ApiError, seg } from '../lib/api'
import { forCreate, forReplace, looksSecret, newRow, problems, rowsOf, type Mode, type Row } from '../lib/params'
import { sqlPreview } from '../lib/sql'
import type { Shape } from '../lib/types'
import { RefField } from '../components/RefField'
import { Banner, ErrorState, Skeleton, useToast } from '../components/ui'

const types = ['s3', 'gcs', 'r2', 'azure', 'postgres', 'mysql', 'mssql', 'http', 'huggingface', 'quack']
const duckTypes = ['VARCHAR', 'INTEGER', 'BIGINT', 'DOUBLE', 'BOOLEAN', 'MAP(VARCHAR, VARCHAR)', 'STRUCT', 'VARCHAR[]']

export function SecretEditor({ mode }: { mode: 'create' | 'replace' }) {
  const params = useParams()
  const { api } = useApp()
  const { secrets } = useLists()
  const existing = mode === 'replace' ? params.name! : undefined
  const shape = useLoad<Shape | undefined>(
    () => (existing ? api.get<Shape>(`/admin/v1/secrets/${seg(existing)}/shape?values=1`).then((r) => r.data) : Promise.resolve(undefined)),
    [api, existing],
  )
  const d = secrets.data?.find((s) => s.name === existing)
  if (existing && (shape.loading || !secrets.data)) return <Skeleton />
  if (shape.error) return <ErrorState error={shape.error} onRetry={shape.reload} />
  return <Form key={existing ?? 'new'} existing={existing} shape={shape.data} initial={d ? { type: d.type, provider: d.provider, scope: d.scope, comment: d.comment } : undefined} />
}

function Form({ existing, shape, initial }: { existing?: string; shape?: Shape; initial?: { type: string; provider: string; scope: string[]; comment: string } }) {
  const { api, service } = useApp()
  const { secrets } = useLists()
  const navigate = useNavigate()
  const toast = useToast()
  const [name, setName] = useState(existing ?? '')
  const [type, setType] = useState(initial?.type ?? 's3')
  const [provider, setProvider] = useState(initial?.provider || 'config')
  const [scope, setScope] = useState<string[]>(initial?.scope ?? [])
  const [scopeInput, setScopeInput] = useState('')
  const [comment, setComment] = useState(initial?.comment ?? '')
  const [rows, setRows] = useState<Row[]>(() => (shape ? rowsOf(shape.params) : [newRow('key_id'), newRow('secret')]))
  const [error, setError] = useState<unknown>(null)
  const [conflict, setConflict] = useState(false)
  const [busy, setBusy] = useState(false)
  const minted = provider === 'token_exchange'
  const issues = useMemo(() => problems(rows), [rows])
  useEffect(() => setConflict(false), [rows])

  const update = (key: string, change: Partial<Row>) => setRows((rs) => rs.map((r) => (r.key === key ? { ...r, ...change } : r)))
  const validName = /^\S(.*\S)?$/.test(name) && name.length <= 200

  const save = async () => {
    setBusy(true)
    setError(null)
    try {
      if (!existing) {
        const body = { type, provider, scope, comment, ...forCreate(rows) }
        await api.call('PUT', `/v1/secrets/${seg(name)}`, body, { 'If-None-Match': '*' })
        toast(`${name} created`)
      } else {
        // the merge keeps what was never seen, on the version read (the type, provider and scope stay)
        await api.call('PATCH', `/admin/v1/secrets/${seg(existing)}/params`, { ...forReplace(rows), comment }, { 'If-Match': `"${shape!.version}"` })
        toast(`${existing} saved`)
      }
      secrets.reload()
      navigate(`/secrets/${seg(existing ?? name)}`)
    } catch (e) {
      if (e instanceof ApiError && e.status === 412) setConflict(true)
      else setError(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col gap-5">
      <header className="flex items-center gap-3">
        <Link to={existing ? `/secrets/${seg(existing)}` : '/secrets'} aria-label="Back" className="icon-btn h-9 w-9 border border-line text-ink"><ArrowLeft size={18} /></Link>
        <div className="flex flex-col leading-[18px]">
          <span className="eyebrow">{existing ? 'Replace secret' : 'New secret'}</span>
          <h1 className="m-0 font-mono text-[20px] font-medium leading-7">{existing ?? (name || 'untitled')}{shape && <span className="text-[13px] text-muted"> from v{shape.version}</span>}</h1>
        </div>
        <div className="ml-auto flex gap-2">
          <Link to={existing ? `/secrets/${seg(existing)}` : '/secrets'} className="btn-secondary no-underline">Cancel</Link>
          <button type="button" className="btn-primary" disabled={busy || issues.size > 0 || (!existing && !validName)} onClick={save}>
            {existing ? `Save as v${Number(shape!.version) + 1}` : 'Create'}
          </button>
        </div>
      </header>
      {conflict && (
        <Banner tone="warning">
          <span className="flex items-center gap-3">
            {existing} changed meanwhile. Your edit is kept: reload to see the new version, then apply yours again.
            <button type="button" className="btn ml-auto border border-current bg-transparent py-1 text-current" onClick={() => window.location.reload()}>Reload</button>
          </span>
        </Banner>
      )}
      {error != null && <ErrorState error={error} />}
      <div className="flex items-start gap-6">
        <div className="flex min-w-0 flex-[999_1_640px] flex-col gap-5">
          <section className="grid grid-cols-3 gap-4 rounded-lg bg-soft p-6">
            <label className="flex flex-col gap-1.5 text-[13px] font-semibold">Name
              <input className="input font-mono" value={name} disabled={!!existing} onChange={(e) => setName(e.target.value)} />
              <span className="font-normal text-muted">{existing ? 'The name stays on replace.' : 'Any text up to 200 characters, no edge spaces.'}</span>
            </label>
            <label className="flex flex-col gap-1.5 text-[13px] font-semibold">Type
              <input className="input font-mono" list="secret-types" value={type} disabled={!!existing} onChange={(e) => setType(e.target.value)} />
              <datalist id="secret-types">{types.map((t) => <option key={t} value={t} />)}</datalist>
            </label>
            <label className="flex flex-col gap-1.5 text-[13px] font-semibold">Provider
              <select className="input" value={provider} disabled={!!existing} onChange={(e) => setProvider(e.target.value)}>
                <option value="config">config</option>
                <option value="token_exchange">token_exchange — a token for each caller</option>
                {!['config', 'token_exchange'].includes(provider) && <option value={provider}>{provider}</option>}
              </select>
            </label>
            <label className="col-span-3 flex flex-col gap-1.5 text-[13px] font-semibold">Comment
              <input className="input" value={comment} onChange={(e) => setComment(e.target.value)} />
            </label>
            <div className="col-span-3 flex flex-col gap-1.5 text-[13px] font-semibold">Scope
              <div className="flex flex-wrap gap-1.5 rounded-sm border border-line bg-surface p-1.5">
                {scope.map((s) => (
                  <span key={s} className="inline-flex items-center gap-1 rounded-full bg-soft py-0.5 pl-3 pr-1 font-mono text-[12px] font-normal">
                    {s}
                    {!existing && <button type="button" className="icon-btn h-5 w-5" aria-label={`Remove ${s}`} onClick={() => setScope(scope.filter((x) => x !== s))}><X size={12} /></button>}
                  </span>
                ))}
                {!existing && (
                  <input aria-label="Add a scope" placeholder="Add a URL prefix, Enter" className="min-w-[200px] flex-1 border-0 bg-transparent font-mono text-[12px] font-normal text-ink outline-none"
                    value={scopeInput} onChange={(e) => setScopeInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && scopeInput.trim()) {
                        e.preventDefault()
                        if (!scope.includes(scopeInput.trim())) setScope([...scope, scopeInput.trim()])
                        setScopeInput('')
                      }
                    }} />
                )}
              </div>
              {existing && <span className="font-normal text-muted">The type, provider and scope are set when a secret is created: to change them, create it anew.</span>}
            </div>
          </section>
          <section aria-label="Parameters" className="flex flex-col gap-2.5">
            <div className="flex items-baseline gap-2.5">
              <h2 className="m-0 text-[16px] font-bold">Parameters</h2>
              <span className="text-[13px] text-muted">
                {minted ? 'No token here: the service mints one per caller. Give the audience (and a scope).' : 'Values not marked secret are shown and edited in place; a secret one is kept or set anew, never shown.'}
              </span>
            </div>
            <div className="overflow-x-auto rounded-md border border-line">
              <table className="w-full min-w-[760px] border-collapse">
                <thead className="bg-soft">
                  <tr>
                    <th className="th w-[180px] pl-3.5">Name</th>
                    <th className="th w-[160px]">Type</th>
                    <th className="th">Value</th>
                    <th className="th w-[90px]" title="redact_keys: never shown, never in duckdb_secrets()">Secret</th>
                    <th className="th w-[48px]"><span className="sr-only">Remove</span></th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => <ParamRow key={r.key} r={r} sources={service.sources} issue={issues.get(r.key)} update={update} />)}
                </tbody>
              </table>
            </div>
            <button type="button" className="btn self-start border border-dashed border-line text-strong" onClick={() => setRows([...rows, newRow()])}>
              <Plus size={15} aria-hidden /> Add a parameter
            </button>
          </section>
        </div>
        <aside aria-label="SQL preview" className="sticky top-4 flex w-[380px] flex-none flex-col gap-2.5">
          <div className="flex items-center gap-2"><Terminal size={16} className="text-brand" aria-hidden /><h2 className="m-0 text-[14px] font-bold">What this amounts to</h2></div>
          <pre className="m-0 whitespace-pre-wrap rounded-md bg-soft p-4 font-mono text-[12px] leading-5">{sqlPreview(name, type, provider, scope, rows)}</pre>
          {existing && <span className="text-[12px] text-muted">Saved with <span className="font-mono">If-Match: "{shape!.version}"</span>: a change made meanwhile is never overwritten.</span>}
        </aside>
      </div>
    </div>
  )
}

function ParamRow({ r, sources, issue, update }: { r: Row; sources: import('../lib/types').Source[]; issue?: string; update: (key: string, c: Partial<Row>) => void }) {
  if (r.removed) {
    return (
      <tr className="border-t border-line bg-soft">
        <td className="td pl-3.5 font-mono text-[13px] text-muted line-through">{r.name}</td>
        <td className="td text-[13px] text-muted" colSpan={3}>removed at the save</td>
        <td className="td"><button type="button" className="btn-ghost py-1 text-[13px]" onClick={() => update(r.key, { removed: false })}>Undo</button></td>
      </tr>
    )
  }
  const modes: [Mode, string][] = [...(r.existing ? [['keep', 'Keep'] as [Mode, string]] : []), ['value', 'Value'], ['ref', 'Reference']]
  const keptSecret = r.existing?.redacted && r.mode === 'keep'
  return (
    <tr className="border-t border-line align-top">
      <td className="td pl-3.5">
        {r.existing ? <span className="font-mono text-[13px]">{r.name}</span> : (
          <input aria-label="Parameter name" className="input w-full py-1.5 font-mono text-[13px]" value={r.name}
            onChange={(e) => update(r.key, { name: e.target.value, secret: r.secret || looksSecret(e.target.value) })} />
        )}
        {issue && <span role="alert" className="mt-1 block text-[12px] text-danger">{issue}</span>}
      </td>
      <td className="td">
        {r.existing && r.mode === 'keep' ? <span className="font-mono text-[12px] text-muted">{r.type}</span> : (
          <input aria-label={`${r.name}: DuckDB type`} list="duck-types" className="input w-full py-1.5 font-mono text-[12px]" value={r.type} onChange={(e) => update(r.key, { type: e.target.value })} />
        )}
        <datalist id="duck-types">{duckTypes.map((t) => <option key={t} value={t} />)}</datalist>
      </td>
      <td className="td">
        <div className="flex flex-wrap items-center gap-2">
          <div role="radiogroup" aria-label={`${r.name}: value`} className="inline-flex rounded-full bg-soft p-0.5">
            {modes.map(([m, label]) => (
              <button key={m} type="button" role="radio" aria-checked={r.mode === m} onClick={() => update(r.key, { mode: m })}
                className={`rounded-full px-3 py-0.5 text-[12px] ${r.mode === m ? 'bg-surface font-semibold text-ink shadow-[inset_0_0_0_1px_var(--border)]' : 'text-muted'}`}>
                {label}
              </button>
            ))}
          </div>
          {r.mode === 'keep' && (
            <span className="inline-flex items-center gap-1.5 text-[13px] text-muted">
              {r.existing?.reference ? <span className="break-all font-mono">{r.existing.reference}</span> : keptSecret ? <><Lock size={14} aria-hidden /> unchanged · secret, not shown</> : <span className="font-mono">{r.value}</span>}
            </span>
          )}
          {r.mode === 'value' && (
            <input aria-label={`${r.name}: value`} type={r.secret ? 'password' : 'text'} autoComplete="off" placeholder={r.existing?.redacted ? 'a new value' : ''}
              className="input min-w-[220px] flex-1 py-1.5 font-mono text-[13px]" value={r.value} onChange={(e) => update(r.key, { value: e.target.value })} />
          )}
          {r.mode === 'ref' && <RefField sources={sources} value={r.ref} label={r.name} onChange={(ref) => update(r.key, { ref })} />}
        </div>
      </td>
      <td className="td text-center">
        <input type="checkbox" aria-label={`${r.name} is secret`} className="h-[18px] w-[18px] accent-[var(--brand-strong)]"
          checked={r.secret || r.mode === 'ref'} disabled={r.mode === 'ref' || keptSecret}
          title={keptSecret ? 'A kept secret stays secret: set a new value to unmark it' : r.mode === 'ref' ? 'A reference is always secret' : undefined}
          onChange={(e) => update(r.key, { secret: e.target.checked })} />
      </td>
      <td className="td">
        <button type="button" className="icon-btn" aria-label={`Remove ${r.name || 'the parameter'}`} onClick={() => update(r.key, { removed: true })}>
          <Trash2 size={16} />
        </button>
      </td>
    </tr>
  )
}
