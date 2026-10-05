// A secret: its descriptor, its shape (names, types, which are secret, references as written; plain values on
// request), its grants, and the statement it amounts to. A dynamic one (token_exchange) says how it is served.
import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ChevronRight, Copy, Eye, EyeOff, Link2, Pencil, Trash2, Zap } from 'lucide-react'
import { useApp, useLoad } from '../context'
import { useLists } from '../lists'
import { nameOf, route, seg } from '../lib/api'
import { rowsOf } from '../lib/params'
import { sqlPreview } from '../lib/sql'
import type { Shape } from '../lib/types'
import { Grants } from '../components/Grants'
import { ConfirmDelete, ErrorState, Masked, Skeleton, VerbChips, useToast } from '../components/ui'

export function SecretDetail() {
  const name = nameOf(useParams().name)
  return <Detail key={name} name={name} /> // a new secret is a new page: nothing shown carries over
}

function Detail({ name }: { name: string }) {
  const { api, service } = useApp()
  const { secrets } = useLists()
  const navigate = useNavigate()
  const toast = useToast()
  const [shown, setShown] = useState(false)
  const [tab, setTab] = useState<'params' | 'sql'>('params')
  const [deleting, setDeleting] = useState<string | null>(null)
  const [editing, setEditing] = useState<string | null>(null)
  const [failure, setFailure] = useState<unknown>(null)
  const shape = useLoad(() => api.get<Shape>(`/admin/v1/secrets/${seg(name)}/shape${shown ? '?values=1' : ''}`).then((r) => r.data), [api, name, shown])
  const d = secrets.data?.find((s) => s.name === name)
  const rows = useMemo(() => rowsOf(shape.data?.params ?? []), [shape.data])
  if (shape.error) return <ErrorState error={shape.error} onRetry={shape.reload} />
  if (secrets.error) return <ErrorState error={secrets.error} onRetry={secrets.reload} />
  if (!shape.data || !secrets.data) return <Skeleton />
  if (!d) {
    // created elsewhere since the list was read
    return (
      <div className="flex flex-col items-start gap-3">
        <span className="text-muted">The list does not have {name} yet.</span>
        <button type="button" className="btn-secondary" onClick={secrets.reload}>Reload the list</button>
      </div>
    )
  }
  const minted = d.provider === 'token_exchange'
  const saveComment = async () => {
    try {
      await api.call('PATCH', `/v1/secrets/${seg(name)}`, { comment: editing })
      setEditing(null)
      secrets.reload()
      toast('Comment saved')
    } catch (e) {
      setFailure(e)
    }
  }
  return (
    <>
      {failure != null && <ErrorState error={failure} />}
      <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-[13px] text-muted">
        <Link to="/secrets">Secrets</Link>
        <ChevronRight size={14} aria-hidden />
        <span className="font-mono">{name}</span>
      </nav>
      <section className="flex flex-wrap items-start gap-5 rounded-lg bg-soft p-6">
        <div className="flex min-w-0 flex-[1_1_520px] flex-col gap-2.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="m-0 font-mono text-[24px] font-medium leading-8">{name}</h1>
            <span className="chip border border-line bg-surface font-mono font-normal">{d.type}</span>
            {minted ? (
              <span className="chip bg-strong text-on-brand"><Zap size={13} aria-hidden /> Dynamic · a token for each caller</span>
            ) : (
              <span className="chip border border-line bg-surface font-normal">provider: {d.provider || 'config'}</span>
            )}
            <span className="chip bg-surface font-mono font-normal text-muted">v{d.version}</span>
          </div>
          {editing === null ? (
            <div className="flex items-center gap-2 text-muted">
              <span>{d.comment || <em>No comment</em>}</span>
              {d.permissions.includes('annotate') && (
                <button type="button" className="icon-btn h-7 w-7" aria-label="Edit the comment" onClick={() => setEditing(d.comment)}>
                  <Pencil size={15} />
                </button>
              )}
            </div>
          ) : (
            <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); saveComment() }}>
              <input className="input flex-1" value={editing} onChange={(e) => setEditing(e.target.value)} aria-label="Comment" autoFocus />
              <button type="submit" className="btn-primary">Save</button>
              <button type="button" className="btn-ghost" onClick={() => setEditing(null)}>Cancel</button>
            </form>
          )}
          {d.scope.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[12px] text-muted">Scope</span>
              {d.scope.map((s) => <span key={s} className="chip bg-surface font-mono font-normal">{s}</span>)}
            </div>
          )}
        </div>
        <dl className="m-0 grid flex-[0_1_380px] grid-cols-2 gap-x-5 gap-y-2.5 text-[13px]">
          <div><dt className="text-muted">Owner</dt><dd className="m-0 truncate font-mono text-[12px]" title={d.owner}>{d.owner}</dd></div>
          <div><dt className="text-muted">Your verbs</dt><dd className="m-0"><VerbChips verbs={d.permissions} /></dd></div>
          <div><dt className="text-muted">Created</dt><dd className="m-0">{new Date(d.created_at).toLocaleString()}</dd></div>
          <div><dt className="text-muted">Updated</dt><dd className="m-0">{new Date(d.updated_at).toLocaleString()}</dd></div>
        </dl>
        <div className="flex gap-2">
          {d.permissions.includes('update') && <Link to={`/secrets/${route(name)}/edit`} className="btn-primary no-underline">Replace</Link>}
          {d.permissions.includes('delete') && (
            <button type="button" className="btn-danger" onClick={() => setDeleting(name)}><Trash2 size={16} aria-hidden /> Delete</button>
          )}
        </div>
      </section>
      <div className="flex items-end gap-1.5 border-b border-line" role="tablist" aria-label="Secret">
        {(['params', 'sql'] as const).map((t) => (
          <button key={t} type="button" role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
            className={`-mb-px border-b-2 px-4 py-2.5 ${tab === t ? 'border-strong font-bold text-ink' : 'border-transparent text-muted'}`}>
            {t === 'params' ? 'Parameters' : 'SQL'}
          </button>
        ))}
        {!minted && (
          <button type="button" aria-pressed={shown} onClick={() => setShown(!shown)}
            className={`btn mb-1.5 ml-auto border border-strong py-1 text-[13px] ${shown ? 'bg-strong text-on-brand' : 'text-strong'}`}>
            {shown ? <EyeOff size={15} aria-hidden /> : <Eye size={15} aria-hidden />} {shown ? 'Hide values' : 'Show values'}
          </button>
        )}
      </div>
      {shown && (
        <span role="status" className="text-[13px] text-muted">
          Showing parameters not marked secret. Secret ones (<span className="font-mono">redact_keys</span>) and the values behind references are never shown. This read is in the audit.
        </span>
      )}
      <div className="flex flex-wrap items-start gap-5">
        <div className="flex min-w-0 flex-[999_1_560px] flex-col gap-5">
          {tab === 'params' ? (
            <div className="overflow-x-auto rounded-md border border-line">
              <table className="w-full min-w-[600px] border-collapse">
                <thead className="bg-soft">
                  <tr><th className="th pl-4">Parameter</th><th className="th">DuckDB type</th><th className="th">Value</th></tr>
                </thead>
                <tbody>
                  {shape.data.params.map((p) => (
                    <tr key={p.name} className="border-t border-line">
                      <td className="td pl-4 font-mono text-[13px]">{p.name}</td>
                      <td className="td font-mono text-[12px] text-muted">{p.type}</td>
                      <td className="td">
                        {p.reference ? (
                          <span className="inline-flex flex-wrap items-center gap-2">
                            <Link2 size={16} className="text-brand" aria-hidden />
                            <span className="break-all font-mono text-[13px]">{p.reference}</span>
                            <span className="chip bg-soft text-strong">source: {/^ref\+([a-z0-9-]+):/.exec(p.reference)?.[1]}</span>
                          </span>
                        ) : p.value !== undefined ? (
                          <span className="break-all font-mono text-[13px]">{typeof p.value === 'string' ? p.value : JSON.stringify((p.value as { value?: unknown }).value ?? p.value)}</span>
                        ) : (
                          <span className="inline-flex items-center gap-2">
                            <Masked label={p.redacted ? 'secret: never shown' : 'hidden: Show values'} />
                            {p.redacted && <span className="chip bg-warning-soft text-warning">secret</span>}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {minted && (
                    <tr className="border-t border-line bg-soft">
                      <td className="td pl-4 font-mono text-[13px]">{d.type === 'quack' ? 'token' : 'bearer_token'}</td>
                      <td className="td font-mono text-[12px] text-muted">VARCHAR</td>
                      <td className="td"><span className="inline-flex items-center gap-2 font-semibold text-strong"><Zap size={15} aria-hidden /> minted per caller · never stored</span></td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          ) : (
            <section aria-label="SQL" className="flex flex-col gap-2.5">
              <div className="flex items-center gap-2 text-[13px] text-muted">
                The statement this secret amounts to, secret values masked.
                <button type="button" className="btn-ghost ml-auto border border-line py-1 text-[13px]"
                  onClick={() => navigator.clipboard.writeText(sqlPreview(name, d.type, d.provider, d.scope, rows)).then(() => toast('Copied'))}>
                  <Copy size={15} aria-hidden /> Copy
                </button>
              </div>
              <pre className="m-0 whitespace-pre-wrap rounded-md bg-soft p-5 font-mono text-[13px] leading-[22px]">{sqlPreview(name, d.type, d.provider, d.scope, rows)}</pre>
            </section>
          )}
          {minted && <MintedServing issuers={service.issuers} checks={service.ready.checks} />}
        </div>
        <aside className="flex flex-[1_1_320px] flex-col gap-5">
          <Grants kind="secrets" name={name} onChange={secrets.reload} />
        </aside>
      </div>
      <ConfirmDelete kind="secret" name={deleting} consequence="DuckDB clients that use it fail their next query."
        onClose={() => setDeleting(null)}
        onConfirm={async () => {
          await api.call('DELETE', `/v1/secrets/${seg(name)}`)
          toast(`${name} deleted`)
          secrets.reload()
          navigate('/secrets')
        }} />
    </>
  )
}

function MintedServing({ issuers, checks }: { issuers: { issuer: string; exchange?: { client_auth: string } }[]; checks: Record<string, string> }) {
  const steps = [
    <>A caller fetches the secret with <span className="font-mono">use</span> — DuckDB directly, or a server acting for a user under a delegation grant.</>,
    <>tresor exchanges the caller's token at <strong>their</strong> identity provider (RFC 8693) for this audience. Under a delegation grant the token is the <strong>user's</strong>, never the server's.</>,
    <>The answer carries the token and an <span className="font-mono">expires_at</span>; DuckDB caches it no longer, and never serves it to another caller.</>,
  ]
  return (
    <section className="card flex flex-col gap-3.5">
      <span className="eyebrow">How a fetch is served</span>
      {steps.map((s, i) => (
        <div key={i} className="flex items-start gap-3">
          <span className="flex h-[26px] w-[26px] flex-none items-center justify-center rounded-full border border-line text-[12px] font-bold text-strong">{i + 1}</span>
          <span>{s}</span>
        </div>
      ))}
      <span className="text-muted">A lasting refusal (the user's session at the IdP ended) is <span className="font-mono">403 mint_refused</span>; an outage is <span className="font-mono">503</span>. Nothing is served instead.</span>
      <span className="eyebrow mt-2">Exchange at the identity providers</span>
      <ul className="m-0 flex list-none flex-col gap-2 p-0">
        {issuers.map((is) => {
          const state = checks[`exchange ${is.issuer}`]
          return (
            <li key={is.issuer} className="flex items-center gap-2 rounded-md bg-soft px-3.5 py-2.5">
              <span className="break-all font-mono text-[12px]">{is.issuer}</span>
              <span className="ml-auto text-[12px] text-muted">{is.exchange ? `client_auth: ${is.exchange.client_auth}` : 'no exchange client'}</span>
              {state && <span className={`text-[12px] font-semibold ${state === 'ok' || state === 'ready' ? 'text-success' : 'text-warning'}`}>{state}</span>}
            </li>
          )
        })}
      </ul>
    </section>
  )
}
