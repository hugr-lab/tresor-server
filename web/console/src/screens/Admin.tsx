// Access (grants by role and group), the references check, and the service as it runs.
import { Fragment, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Check, CheckCircle2, CircleAlert, Search, Users } from 'lucide-react'
import { useApp, useLoad } from '../context'
import { useLists } from '../lists'
import { route, seg } from '../lib/api'
import type { DataKeysInfo, Finding, Grant } from '../lib/types'
import { idFor } from '../lib/grants'
import { Empty, ErrorState, PageTitle, Skeleton, useToast } from '../components/ui'

interface GrantsAnswer {
  principals: { principal: string; count: number }[]
  entries?: { kind: 'secret' | 'variable'; name: string; grant_id: string; others: string[] }[]
}

/** grants principal use of an entry: its existing grant's id, else tresor's - one grant, as from SQL */
async function grant(api: import('../lib/api').Api, kind: string, name: string, principal: string) {
  const existing = (await api.get<Grant[]>(`/v1/${kind}s/${seg(name)}/grants`)).data
  await api.call('PUT', `/v1/${kind}s/${seg(name)}/grants/${seg(idFor(existing, principal))}`, { principal, verbs: ['use'] })
}

/** every grant of principal on an entry: one made from SQL and one from elsewhere may both be there */
async function revoke(api: import('../lib/api').Api, kind: string, name: string, principal: string) {
  const existing = (await api.get<Grant[]>(`/v1/${kind}s/${seg(name)}/grants`)).data
  for (const g of existing.filter((x) => x.principal === principal)) {
    await api.call('DELETE', `/v1/${kind}s/${seg(name)}/grants/${seg(g.id)}`)
  }
}

export function Access() {
  const { api } = useApp()
  const lists = useLists()
  const toast = useToast()
  const [params, setParams] = useSearchParams()
  const principal = params.get('principal') ?? ''
  const [query, setQuery] = useState('')
  const [entry, setEntry] = useState('')
  const [error, setError] = useState<unknown>(null)
  const all = useLoad(() => api.get<GrantsAnswer>('/admin/v1/grants').then((r) => r.data), [api])
  const one = useLoad(
    () => (principal ? api.get<GrantsAnswer>(`/admin/v1/grants?principal=${encodeURIComponent(principal)}`).then((r) => r.data) : Promise.resolve(undefined)),
    [api, principal],
  )
  const principals = useMemo(
    () => (all.data?.principals ?? []).filter((p) => p.principal.toLowerCase().includes(query.trim().toLowerCase())),
    [all.data, query],
  )
  const choices = [
    ...(lists.secrets.data ?? []).map((s) => `secret:${s.name}`),
    ...(lists.variables.data ?? []).map((v) => `variable:${v.name}`),
  ]
  const change = async (f: () => Promise<unknown>, done: string) => {
    setError(null)
    try {
      await f()
      toast(done)
      all.reload()
      one.reload()
    } catch (e) {
      setError(e)
    }
  }
  const pick = (p: string) => setParams(p ? { principal: p } : {})
  const newPrincipal = /^(role|group):\S+$/.test(query.trim()) && !all.data?.principals.some((p) => p.principal === query.trim())
  return (
    <>
      <PageTitle title="Access">
        <span className="pb-1 text-muted">
          What each role and group may use. People get access through the roles and groups their identity provider gives them:
          a grant names a <span className="font-mono">role:</span> or a <span className="font-mono">group:</span>, never a person.
        </span>
      </PageTitle>
      {all.error != null && <ErrorState error={all.error} onRetry={all.reload} />}
      <div className="flex items-start gap-5">
        <section aria-label="Roles and groups" className="flex w-[320px] flex-none flex-col gap-2.5">
          <label className="flex items-center gap-2 rounded-full border border-line px-3.5 py-1.5 text-muted">
            <Search size={15} aria-hidden />
            <span className="sr-only">Find a role or group</span>
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Find, or role:… / group:…"
              className="min-w-0 flex-1 border-0 bg-transparent text-ink outline-none" />
          </label>
          {newPrincipal && (
            <button type="button" className="btn-secondary self-start py-1 text-[13px]" onClick={() => pick(query.trim())}>Grant to {query.trim()}</button>
          )}
          {all.loading && !all.data && <Skeleton rows={4} />}
          <ul className="m-0 flex list-none flex-col gap-1 p-0">
            {principals.map((p) => (
              <li key={p.principal}>
                <button type="button" aria-current={p.principal === principal} onClick={() => pick(p.principal)}
                  className={`flex w-full items-center gap-2.5 rounded-full px-3.5 py-2 text-left ${p.principal === principal ? 'border border-strong bg-soft font-semibold' : 'border border-transparent hover:bg-soft'}`}>
                  <Users size={16} aria-hidden />
                  <span className="flex-1 font-mono text-[13px]">{p.principal}</span>
                  <span className="text-[12px] text-muted">{p.count}</span>
                </button>
              </li>
            ))}
          </ul>
          {all.data && all.data.principals.length === 0 && <span className="text-[13px] text-muted">No grants yet.</span>}
        </section>
        <section aria-label="Granted" className="flex min-w-0 flex-1 flex-col gap-3.5 rounded-lg bg-soft p-6">
          {!principal ? (
            <Empty icon={<Users size={36} />} title="Pick a role or group">
              <span className="text-muted">Its entries appear here: what it may use, and who else may.</span>
            </Empty>
          ) : (
            <>
              <div className="flex items-center gap-2.5">
                <h2 className="m-0 font-mono text-[20px] font-medium">{principal}</h2>
                <span className="text-muted">{one.data?.entries ? `may use ${one.data.entries.length} ${one.data.entries.length === 1 ? 'entry' : 'entries'}` : '…'}</span>
              </div>
              <form className="flex gap-2" onSubmit={(e) => {
                e.preventDefault()
                const [kind, ...rest] = entry.split(':')
                const name = rest.join(':')
                if (!choices.includes(entry)) return
                change(() => grant(api, kind, name, principal), `${principal} may use ${name}`)
                  .then(() => setEntry(''))
              }}>
                <label className="flex flex-1 items-center rounded-sm border border-line bg-surface px-3 py-1.5">
                  <span className="sr-only">A secret or variable</span>
                  <input list="entries" value={entry} onChange={(e) => setEntry(e.target.value)} placeholder="Grant a secret or variable…"
                    className="min-w-0 flex-1 border-0 bg-transparent font-mono text-[13px] text-ink outline-none" />
                  <datalist id="entries">{choices.map((c) => <option key={c} value={c} />)}</datalist>
                </label>
                <button type="submit" className="btn-primary" disabled={!choices.includes(entry)}>Grant use</button>
              </form>
              {error != null && <ErrorState error={error} />}
              {one.error != null && <ErrorState error={one.error} onRetry={one.reload} />}
              <div className="overflow-x-auto rounded-md border border-line bg-surface">
                <table className="w-full min-w-[560px] border-collapse">
                  <thead><tr><th className="th pl-4">Entry</th><th className="th">Kind</th><th className="th">Also granted to</th><th className="th"><span className="sr-only">Revoke</span></th></tr></thead>
                  <tbody>
                    {(one.data?.entries ?? []).map((e) => (
                      <tr key={`${e.kind}/${e.name}/${e.grant_id}`} className="border-t border-line">
                        <td className="td pl-4"><Link to={`/${e.kind}s/${route(e.name)}`} className="font-mono text-[13px]">{e.name}</Link></td>
                        <td className="td text-[13px] text-muted">{e.kind}</td>
                        <td className="td font-mono text-[12px] text-muted">{e.others.join(', ') || '—'}</td>
                        <td className="td text-right">
                          <button type="button" className="btn-ghost border border-line py-1 text-[13px]"
                            onClick={() => change(() => revoke(api, e.kind, e.name, principal), `${principal} may no longer use ${e.name}`)}>
                            Revoke
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <span className="text-[12px] text-muted">Each change is one grant write on the entry, at once: there is no batch to undo.</span>
            </>
          )}
        </section>
      </div>
    </>
  )
}

export function RefsCheck() {
  const { api } = useApp()
  const [state, setState] = useState<{ running?: boolean; resolve?: boolean; checked?: number; findings?: Finding[]; error?: unknown; at?: Date }>({})
  const run = async (resolve: boolean) => {
    setState({ running: true, resolve })
    const started = Date.now()
    try {
      const r = await api.call<{ checked: number; findings: Finding[] }>('POST', '/admin/v1/refs-check', { resolve })
      setState({ resolve, checked: r.data.checked, findings: r.data.findings, at: new Date(started) })
    } catch (error) {
      setState({ resolve, error })
    }
  }
  const n = state.findings?.length ?? 0
  return (
    <>
      <PageTitle title="References check">
        <span className="pb-1 text-muted">
          Every <span className="font-mono">ref+…</span> in secrets and variables, checked against the sources as configured now. Run it before a
          configuration change: a renamed source or a narrowed allowlist strands references.
        </span>
      </PageTitle>
      <div className="flex gap-2">
        <button type="button" className="btn-primary" disabled={state.running} onClick={() => run(false)}>Check</button>
        <button type="button" className="btn-secondary" disabled={state.running} onClick={() => run(true)}>Check and read each</button>
        {state.running && <span className="self-center text-muted">{state.resolve ? 'Reading every reference…' : 'Checking…'}</span>}
      </div>
      {state.error != null && <ErrorState error={state.error} />}
      {state.findings && (
        <>
          <div className="grid grid-cols-3 gap-4">
            <div className="flex flex-col rounded-md bg-soft px-5 py-4"><span className="text-[13px] text-muted">Entries checked</span><span className="text-[28px] font-bold leading-9">{state.checked}</span></div>
            <div className={`flex flex-col rounded-md px-5 py-4 ${n ? 'bg-danger-soft text-danger' : 'bg-success-soft text-success'}`}>
              <span className="text-[13px]">Findings</span><span className="text-[28px] font-bold leading-9">{n}</span>
            </div>
            <div className="flex flex-col justify-center rounded-md bg-soft px-5 py-4 text-[13px] text-muted">
              {state.resolve ? 'Parsed, allowlists checked, and each one read' : 'Parsed and allowlists checked'} · {state.at?.toLocaleTimeString()}
            </div>
          </div>
          {n === 0 ? (
            <div className="flex items-center gap-3 rounded-md bg-success-soft p-5 text-success"><CheckCircle2 size={22} aria-hidden /><strong>Every reference resolves as configured.</strong></div>
          ) : (
            <div className="overflow-x-auto rounded-md border border-line">
              <table className="w-full min-w-[820px] border-collapse">
                <thead className="bg-soft"><tr><th className="th pl-4">Entry</th><th className="th">Parameter</th><th className="th">Reason</th></tr></thead>
                <tbody>
                  {state.findings.map((f, i) => (
                    <tr key={i} className="border-t border-line">
                      <td className="td pl-4"><span className="chip mr-2 border border-line font-normal text-muted">{f.kind}</span><Link to={`/${f.kind}s/${route(f.name)}`} className="font-mono text-[13px]">{f.name}</Link></td>
                      <td className="td font-mono text-[13px]">{f.param}</td>
                      <td className="td"><span className="flex gap-2"><CircleAlert size={16} className="mt-[3px] flex-none text-danger" aria-hidden /><span className="break-all font-mono text-[13px]">{f.reason}</span></span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </>
  )
}

const days = (seconds: number) => {
  const d = Math.floor(seconds / 86400)
  return d === 1 ? '1 day' : `${d} days`
}

/** the data keys' state (spec 019), asked here only: how many, how old, and whether a command is due */
function DataKeys() {
  const { api } = useApp()
  const state = useLoad(() => api.get<DataKeysInfo>('/admin/v1/data-keys').then((r) => r.data), [api])
  if (state.loading) return <Skeleton rows={2} />
  const keys = state.data
  if (!keys) return <span className="text-[12px] text-warning">Data keys: they could not be read.</span>
  return (
    <>
      <dl className="m-0 grid grid-cols-[160px_1fr] gap-x-4 gap-y-2 text-[13px]" aria-label="Data keys">
        <dt className="text-muted">Data keys</dt><dd className="m-0 font-mono">{keys.stored}</dd>
        {keys.stored > 0 && (
          <>
            <dt className="text-muted">Active one's age</dt><dd className="m-0 font-mono">{days(keys.active_age)}</dd>
            <dt className="text-muted">Oldest one's age</dt><dd className="m-0 font-mono">{days(keys.oldest_age)}</dd>
          </>
        )}
      </dl>
      {keys.rows_behind > 0 && (
        <span className="rounded-sm bg-soft px-3 py-2 text-[12px]">
          {keys.rows_behind === 1 ? '1 row is' : `${keys.rows_behind} rows are`} under older data keys: <span className="font-mono">tresor-server reseal</span> moves them to the active one.
        </span>
      )}
      {keys.unused > 0 && (
        <span className="rounded-sm bg-soft px-3 py-2 text-[12px]">
          {keys.unused === 1 ? '1 data key is' : `${keys.unused} data keys are`} used by no row: <span className="font-mono">tresor-server reseal -retire</span> deletes them.
        </span>
      )}
    </>
  )
}

export function Service() {
  const { service: s } = useApp()
  return (
    <>
      <PageTitle title="Service">
        <span className={`chip ${s.ready.ready ? 'bg-success-soft text-success' : 'bg-warning-soft text-warning'}`}><Check size={14} aria-hidden /> {s.ready.ready ? 'Ready' : 'Not ready'}</span>
        <span className="font-mono text-[13px] text-muted">tresor-server {s.version} · {s.protocol}</span>
      </PageTitle>
      <div className="grid grid-cols-2 gap-5">
        <section className="card flex flex-col gap-3">
          <span className="eyebrow">Readiness</span>
          <ul className="m-0 flex list-none flex-col gap-2 p-0">
            {Object.entries(s.ready.checks).sort().map(([name, state]) => (
              <li key={name} className="flex items-center gap-2.5 rounded-full bg-soft px-3.5 py-2">
                <span className="break-all font-mono text-[13px]">{name}</span>
                <span className={`ml-auto text-[12px] font-semibold ${state === 'ok' || state === 'ready' ? 'text-success' : 'text-warning'}`}>{state}</span>
              </li>
            ))}
          </ul>
          <span className="text-[12px] text-muted">A degraded check does not stop the service: only what needs it fails.</span>
        </section>
        <section className="card flex flex-col gap-3">
          <span className="eyebrow">Encryption</span>
          <dl className="m-0 grid grid-cols-[160px_1fr] gap-x-4 gap-y-2 text-[13px]">
            <dt className="text-muted">KEK</dt><dd className="m-0 font-mono">{s.kek.kind || '—'}</dd>
            <dt className="text-muted">Current version</dt><dd className="m-0 break-all font-mono">{s.kek.current ?? s.kek.error ?? '—'}</dd>
            <dt className="text-muted">State store</dt><dd className="m-0 font-mono">{s.state}</dd>
            {s.kek.previous?.map((p, i) => (
              <Fragment key={i}>
                <dt className="text-muted">{i === 0 ? 'Previous (read only)' : ''}</dt>
                <dd className="m-0 break-all font-mono">{p.kind} · {p.key}</dd>
              </Fragment>
            ))}
          </dl>
          {!!s.kek.previous?.length && (
            <span className="rounded-sm bg-warning-soft px-3 py-2 text-[12px] text-warning">
              A move to another KEK is under way: data keys under a previous KEK still open. Run <span className="font-mono">tresor-server rewrap</span>, then remove <span className="font-mono">keys.previous</span>.
            </span>
          )}
          {s.data_keys && <DataKeys />}
          <span className="text-[12px] text-muted">The KEK stays in its store (a file, Key Vault, Transit): shown here is only its kind and the version data keys are wrapped with now.</span>
        </section>
        <section className="card flex flex-col gap-3">
          <span className="eyebrow">Identity providers</span>
          {s.issuers.map((i) => (
            <dl key={i.issuer} className="m-0 grid grid-cols-[160px_1fr] gap-x-4 gap-y-1 text-[13px]">
              <dt className="text-muted">Issuer</dt><dd className="m-0 break-all font-mono">{i.issuer}</dd>
              <dt className="text-muted">Audience</dt><dd className="m-0 font-mono">{i.audience}</dd>
              {i.exchange && <><dt className="text-muted">Token exchange</dt><dd className="m-0 font-mono">client_auth: {i.exchange.client_auth}</dd></>}
            </dl>
          ))}
        </section>
        <section className="card flex flex-col gap-3">
          <span className="eyebrow">Capabilities and policy</span>
          <div className="flex flex-wrap gap-1.5">{s.capabilities.map((c) => <span key={c} className="chip bg-soft font-mono font-normal">{c}</span>)}</div>
          <dl className="m-0 grid grid-cols-[160px_1fr] gap-x-4 gap-y-2 text-[13px]">
            <dt className="text-muted">Administrators</dt><dd className="m-0 font-mono">{s.policy.admins.join(', ')}</dd>
            <dt className="text-muted">Actors</dt><dd className="m-0 font-mono">{s.policy.actors.map((a) => `${a.principal} (${a.verbs.join(', ')})`).join('; ') || '—'}</dd>
            <dt className="text-muted">Audit</dt><dd className="m-0">{s.audit}</dd>
          </dl>
        </section>
      </div>
      <section className="card flex flex-col gap-3">
        <span className="eyebrow">Reference sources</span>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] border-collapse">
            <thead><tr><th className="th pl-0">Name</th><th className="th">Kind</th><th className="th">Connection</th>
              <th className="th" title="Where references may point: set in the configuration (material.*.allow); a reference elsewhere is refused">May read</th><th className="th">Cache</th></tr></thead>
            <tbody>
              {s.sources.map((src) => (
                <tr key={src.name} className="border-t border-line">
                  <td className="td pl-0 font-mono text-[13px] font-medium">ref+{src.name}://</td>
                  <td className="td font-mono text-[12px]">{src.kind}</td>
                  <td className="td break-all font-mono text-[12px] text-muted">{src.connection}</td>
                  <td className="td font-mono text-[12px]">{src.allow.join(', ')}</td>
                  <td className="td text-[12px] text-muted">{src.cache_ttl === '0s' ? 'none' : src.cache_ttl}</td>
                </tr>
              ))}
              {s.sources.length === 0 && <tr><td className="td pl-0 text-muted" colSpan={5}>No source: references are refused.</td></tr>}
            </tbody>
          </table>
        </div>
        <span className="text-[12px] text-muted">
          <strong className="text-ink">May read</strong> — where references of this source may point (<span className="font-mono">material.*.allow</span>). A reference elsewhere is refused when written and when read: the service's own access to the vault is wider than what administrators may reach through it.
        </span>
      </section>
    </>
  )
}
