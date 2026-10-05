// Variables: named strings DuckDB reads by name. One is sensitive when its value is a reference - the service's
// verdict, not a choice: the value behind it is never shown here.
import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Eye, Link2, Plus, Variable } from 'lucide-react'
import { useApp, useLoad } from '../context'
import { useLists } from '../lists'
import { ApiError, nameOf, route, seg } from '../lib/api'
import { ago } from '../lib/time'
import type { Shape } from '../lib/types'
import { Grants } from '../components/Grants'
import { RefField } from '../components/RefField'
import { Banner, ConfirmDelete, Empty, ErrorState, PageTitle, Pager, RowMenu, SearchBox, Skeleton, usePaging, useToast } from '../components/ui'

export function Variables() {
  const { api } = useApp()
  const { variables } = useLists()
  const navigate = useNavigate()
  const toast = useToast()
  const param = useParams().name
  const selected = param === undefined ? undefined : nameOf(param)
  const [query, setQuery] = useState('')
  const [deleting, setDeleting] = useState<string | null>(null)
  const all = variables.data ?? []
  const matched = useMemo(() => {
    const q = query.trim().toLowerCase()
    return all.filter((v) => !q || `${v.name} ${v.comment}`.toLowerCase().includes(q)).sort((a, b) => a.name.localeCompare(b.name))
  }, [all, query])
  const { rows, pager, reset } = usePaging(matched)
  return (
    <>
      <PageTitle title="Variables">
        <span className="pb-1 text-muted">Named strings DuckDB reads by name: buckets, endpoints, settings.</span>
        <Link to="/create/variable" className="btn-primary ml-auto no-underline"><Plus size={16} aria-hidden /> New variable</Link>
      </PageTitle>
      <div role="search" className="flex items-center gap-2">
        <SearchBox value={query} onChange={(v) => { setQuery(v); reset() }} placeholder="Name or comment" label="Filter variables" />
      </div>
      {variables.error != null && <ErrorState error={variables.error} onRetry={variables.reload} />}
      {variables.loading && !variables.data && <Skeleton />}
      {variables.data && all.length === 0 && (
        <Empty icon={<Variable size={40} />} title="No variables yet">
          <span className="text-muted">Create one here, or from DuckDB with tresor.</span>
        </Empty>
      )}
      {variables.data && all.length > 0 && (
        <div className="flex items-start gap-5">
          <div className="flex min-w-0 flex-[999_1_560px] flex-col gap-3">
            <div className="overflow-x-auto rounded-md border border-line">
              <table className="w-full min-w-[640px] border-collapse">
                <thead className="bg-soft">
                  <tr>
                    <th className="th pl-4">Name</th><th className="th">Comment</th><th className="th">Updated</th>
                    <th className="th" title="Set by the service: a value that is a reference (ref+…) is sensitive">Value</th>
                    <th className="th"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((v) => (
                    <tr key={v.name} className={`border-t border-line hover:bg-row ${v.name === selected ? 'bg-row' : ''}`}>
                      <td className="td pl-4"><Link to={`/variables/${route(v.name)}`} className="font-mono font-medium no-underline">{v.name}</Link></td>
                      <td className="td text-muted">{v.comment}</td>
                      <td className="td whitespace-nowrap">{ago(v.updated_at)}</td>
                      <td className="td">
                        {v.sensitive ? (
                          <span className="chip bg-warning-soft text-warning" title="A reference: resolved at each read, handled as secret material"><Link2 size={12} aria-hidden /> sensitive · reference</span>
                        ) : <span className="text-[12px] text-muted">plain</span>}
                      </td>
                      <td className="td text-right">
                        <RowMenu label={v.name} items={[
                          { label: 'Open', onSelect: () => navigate(`/variables/${route(v.name)}`) },
                          { label: 'Replace', onSelect: () => navigate(`/variables/${route(v.name)}/edit`) },
                          { label: 'Delete…', danger: true, onSelect: () => setDeleting(v.name) },
                        ]} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager {...pager} total={all.length} />
          </div>
          {selected && <VariableDetail key={selected} name={selected} onDelete={() => setDeleting(selected)} />}
        </div>
      )}
      <ConfirmDelete kind="variable" name={deleting} consequence="Queries that read it fail."
        onClose={() => setDeleting(null)}
        onConfirm={async () => {
          await api.call('DELETE', `/v1/variables/${seg(deleting!)}`)
          toast(`${deleting} deleted`)
          setDeleting(null)
          variables.reload()
          navigate('/variables')
        }} />
    </>
  )
}

function VariableDetail({ name, onDelete }: { name: string; onDelete: () => void }) {
  const { api } = useApp()
  const { variables } = useLists()
  const [shown, setShown] = useState(false)
  const v = variables.data?.find((x) => x.name === name)
  const shape = useLoad(() => api.get<Shape>(`/admin/v1/variables/${seg(name)}/shape${shown ? '?values=1' : ''}`).then((r) => r.data), [api, name, shown])
  if (!v) return null
  const p = shape.data?.params.find((x) => x.name === 'value')
  return (
    <aside aria-label="Selected variable" className="flex flex-[1_1_360px] flex-col gap-3.5 rounded-lg bg-soft p-6">
      <span className="eyebrow">Variable</span>
      <h2 className="m-0 font-mono text-[20px] font-medium">{name}</h2>
      <span className="text-muted">{v.comment}</span>
      <span className="text-[12px] text-muted">
        {v.sensitive ? 'Sensitive: its value is a reference. The service sets this; it is not a choice.'
          : 'Plain: its value is stored here. Make it a reference to keep it in a vault (it then becomes sensitive).'}
      </span>
      {shape.error != null && <ErrorState error={shape.error} />}
      <div className="flex flex-col gap-2">
        <span className="text-[13px] font-semibold">Value</span>
        {p?.reference ? (
          <div className="flex flex-col gap-1.5 rounded-md border border-line bg-surface px-3.5 py-3">
            <span className="break-all font-mono text-[13px]">{p.reference}</span>
            <span className="text-[12px] text-muted">Resolved at each read. The value behind it is never shown here; DuckDB receives it as secret material.</span>
          </div>
        ) : p?.value !== undefined ? (
          <div className="break-all rounded-md border border-line bg-surface px-3.5 py-3 font-mono text-[13px]">{String(p.value)}</div>
        ) : (
          <button type="button" className="btn-secondary self-start py-1 text-[13px]" onClick={() => setShown(true)}><Eye size={15} aria-hidden /> Show value</button>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Link to={`/variables/${route(name)}/edit`} className="btn-secondary py-1 text-[13px] no-underline">Replace</Link>
        <button type="button" className="btn-danger py-1 text-[13px]" onClick={onDelete}>Delete…</button>
      </div>
      <Grants kind="variables" name={name} onChange={variables.reload} />
      <div className="flex flex-col gap-1.5">
        <span className="text-[13px] font-semibold">Use in DuckDB</span>
        <pre className="m-0 whitespace-pre-wrap rounded-md border border-line bg-surface p-3.5 font-mono text-[12px] leading-5">{`SELECT * FROM tresor_variables();\nSELECT getvariable('${name.replace(/'/g, "''")}');`}</pre>
      </div>
    </aside>
  )
}

export function VariableEditor({ mode }: { mode: 'create' | 'replace' }) {
  const param = useParams().name
  const existing = param === undefined ? undefined : nameOf(param)
  const { api, service } = useApp()
  const { variables } = useLists()
  const navigate = useNavigate()
  const toast = useToast()
  const shape = useLoad<Shape | undefined>(
    () => (mode === 'replace' ? api.get<Shape>(`/admin/v1/variables/${seg(existing!)}/shape?values=1`).then((r) => r.data) : Promise.resolve(undefined)),
    [api, existing, mode],
  )
  const current = variables.data?.find((v) => v.name === existing)
  if (shape.error) return <ErrorState error={shape.error} onRetry={shape.reload} />
  if (mode === 'replace' && (shape.loading || !variables.data)) return <Skeleton />
  const p = shape.data?.params.find((x) => x.name === 'value')
  return (
    <VariableForm existing={mode === 'replace' ? existing : undefined} version={shape.data?.version} initialComment={current?.comment ?? ''}
      initialValue={p?.reference ?? (p?.value !== undefined ? String(p.value) : '')} isRef={!!p?.reference} sources={service.sources}
      onSave={async (name, value, comment, version) => {
        await api.call('PUT', `/v1/variables/${seg(name)}`, { value, comment }, version ? { 'If-Match': `"${version}"` } : { 'If-None-Match': '*' })
        toast(`${name} saved`)
        variables.reload()
        navigate(`/variables/${route(name)}`)
      }} />
  )
}

function VariableForm({ existing, version, initialComment, initialValue, isRef, sources, onSave }: {
  existing?: string; version?: string; initialComment: string; initialValue: string; isRef: boolean
  sources: import('../lib/types').Source[]; onSave: (name: string, value: string, comment: string, version?: string) => Promise<void>
}) {
  const [name, setName] = useState(existing ?? '')
  const [comment, setComment] = useState(initialComment)
  const [mode, setMode] = useState<'value' | 'ref'>(isRef ? 'ref' : 'value')
  const [value, setValue] = useState(isRef ? '' : initialValue)
  const [ref, setRef] = useState(isRef ? initialValue : '')
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const final = mode === 'ref' ? ref : value
  const tooLong = new TextEncoder().encode(final).length > 64 * 1024
  return (
    <div className="flex flex-col gap-5">
      <header className="flex items-center gap-3">
        <Link to={existing ? `/variables/${route(existing)}` : '/variables'} aria-label="Back" className="icon-btn h-9 w-9 border border-line text-ink"><ArrowLeft size={18} /></Link>
        <div className="flex flex-col leading-[18px]">
          <span className="eyebrow">{existing ? 'Replace variable' : 'New variable'}</span>
          <h1 className="m-0 font-mono text-[20px] font-medium leading-7">{existing ?? (name || 'untitled')}</h1>
        </div>
        <div className="ml-auto flex gap-2">
          <Link to={existing ? `/variables/${route(existing)}` : '/variables'} className="btn-secondary no-underline">Cancel</Link>
          <button type="button" className="btn-primary" disabled={busy || !name.trim() || (mode === 'ref' && !ref) || tooLong}
            onClick={async () => {
              setBusy(true)
              setError(null)
              try {
                await onSave(name.trim(), final, comment, version)
              } catch (e) {
                setError(e instanceof ApiError && e.status === 412 ? new ApiError({ ...e.problem, detail: 'it changed meanwhile: reload and apply your edit again' }) : e)
              } finally {
                setBusy(false)
              }
            }}>
            {existing ? 'Save' : 'Create'}
          </button>
        </div>
      </header>
      {error != null && <ErrorState error={error} />}
      <section className="flex max-w-[880px] flex-col gap-4 rounded-lg bg-soft p-6">
        <label className="flex flex-col gap-1.5 text-[13px] font-semibold">Name
          <input className="input font-mono" value={name} disabled={!!existing} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="flex flex-col gap-1.5 text-[13px] font-semibold">Comment
          <input className="input" value={comment} onChange={(e) => setComment(e.target.value)} />
        </label>
        <div className="flex flex-col gap-2 text-[13px] font-semibold">Value
          <div role="radiogroup" aria-label="The value" className="inline-flex self-start rounded-full bg-surface p-0.5">
            {(['value', 'ref'] as const).map((m) => (
              <button key={m} type="button" role="radio" aria-checked={mode === m} onClick={() => setMode(m)}
                className={`rounded-full px-3 py-0.5 text-[12px] ${mode === m ? 'bg-soft font-semibold text-ink' : 'font-normal text-muted'}`}>
                {m === 'value' ? 'Text' : 'Reference'}
              </button>
            ))}
          </div>
          {mode === 'value' ? (
            <textarea className="input min-h-[120px] font-mono text-[13px] font-normal" value={value} onChange={(e) => setValue(e.target.value)} />
          ) : (
            <RefField sources={sources} value={ref} label="value" onChange={setRef} />
          )}
          <span className="font-normal text-muted">
            {mode === 'ref' ? 'A reference makes the variable sensitive: its value stays in the vault, read at each fetch.' : 'Up to 64 KiB of text.'}
            {tooLong && <span className="text-danger"> Longer than 64 KiB.</span>}
          </span>
        </div>
      </section>
      <Banner tone="info">A plain value is shown to administrators here and read by every role granted it; keep material in a vault, by reference.</Banner>
    </div>
  )
}
