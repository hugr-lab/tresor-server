// Secrets: every descriptor the service has (no values), filtered, searched and paged here.
import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Database, Globe, KeyRound, Link2, Plus, Zap } from 'lucide-react'
import { useApp } from '../context'
import { useLists } from '../lists'
import { seg } from '../lib/api'
import { ago } from '../lib/time'
import type { Descriptor } from '../lib/types'
import { Banner, ConfirmDelete, Empty, ErrorState, FilterChip, PageTitle, Pager, RowMenu, SearchBox, Skeleton, VerbChips, usePaging, useToast } from '../components/ui'

const filters = {
  all: () => true,
  dynamic: (s: Descriptor) => s.dynamic,
  granted: (s: Descriptor) => s.permissions.includes('use'),
} as const

const typeIcon = (t: string) => (/^(http|https)$/i.test(t) ? Globe : /^(s3|gcs|r2|azure)$/i.test(t) ? Database : Database)

export function Secrets() {
  const { api, me } = useApp()
  const { secrets } = useLists()
  const navigate = useNavigate()
  const toast = useToast()
  const [filter, setFilter] = useState<keyof typeof filters>('all')
  const [query, setQuery] = useState('')
  const [deleting, setDeleting] = useState<string | null>(null)
  const all = secrets.data ?? []
  const matched = useMemo(() => {
    const q = query.trim().toLowerCase()
    return all
      .filter(filters[filter])
      .filter((s) => !q || `${s.name} ${s.type} ${s.comment} ${s.scope.join(' ')}`.toLowerCase().includes(q))
      .sort((a, b) => a.name.localeCompare(b.name))
  }, [all, filter, query])
  const { rows, pager, reset } = usePaging(matched)
  const mayCreate = me.permissions.create !== false
  return (
    <>
      <PageTitle title="Secrets">
        <span className="pb-1 text-muted">{all.length} secrets · DuckDB fetches material at query time; you manage, roles use.</span>
        {mayCreate && (
          <Link to="/secrets/new" className="btn-primary ml-auto no-underline">
            <Plus size={16} aria-hidden /> New secret
          </Link>
        )}
      </PageTitle>
      <div role="search" className="flex flex-wrap items-center gap-2">
        <SearchBox value={query} onChange={(v) => { setQuery(v); reset() }} placeholder="Name, type, comment or scope" label="Filter secrets" />
        <FilterChip on={filter === 'all'} onClick={() => { setFilter('all'); reset() }}>All</FilterChip>
        <FilterChip on={filter === 'dynamic'} onClick={() => { setFilter('dynamic'); reset() }}>Dynamic</FilterChip>
        <FilterChip on={filter === 'granted'} onClick={() => { setFilter('granted'); reset() }}>Granted to me</FilterChip>
      </div>
      {secrets.error != null && <ErrorState error={secrets.error} onRetry={secrets.reload} />}
      {secrets.loading && !secrets.data && <Skeleton />}
      {secrets.data && all.length === 0 && (
        <Empty icon={<KeyRound size={40} />} title="No secrets yet">
          <span className="text-muted">Create one here, or from DuckDB: <span className="font-mono">CREATE PERSISTENT SECRET … IN tresor</span>.</span>
        </Empty>
      )}
      {secrets.data && all.length > 0 && (
        <>
          <div className="overflow-x-auto rounded-md border border-line">
            <table className="w-full min-w-[960px] border-collapse">
              <thead className="bg-soft">
                <tr>
                  <th className="th pl-4">Name</th>
                  <th className="th">Type</th>
                  <th className="th">Scope</th>
                  <th className="th">Comment</th>
                  <th className="th">Updated</th>
                  <th className="th">Your verbs</th>
                  <th className="th"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((s) => {
                  const Icon = typeIcon(s.type)
                  return (
                    <tr key={s.name} className="border-t border-line hover:bg-row">
                      <td className="td pl-4">
                        <div className="flex flex-col gap-1">
                          <Link to={`/secrets/${seg(s.name)}`} className="font-mono font-medium no-underline">{s.name}</Link>
                          {s.dynamic && (
                            <span className="chip w-fit bg-soft text-muted"><Zap size={12} aria-hidden /> dynamic · token per caller</span>
                          )}
                        </div>
                      </td>
                      <td className="td">
                        <span className="inline-flex items-center gap-1.5 whitespace-nowrap font-mono text-[13px]">
                          <Icon size={16} className="text-brand" aria-hidden /> {s.type}
                        </span>
                      </td>
                      <td className="td max-w-[220px] truncate font-mono text-[13px] text-muted" title={s.scope.join('\n')}>{s.scope.join(', ')}</td>
                      <td className="td max-w-[260px] text-muted">{s.comment}</td>
                      <td className="td whitespace-nowrap">
                        <div className="flex flex-col leading-[18px]">
                          <span title={s.updated_at}>{ago(s.updated_at)}</span>
                          <span className="font-mono text-[12px] text-muted">v{s.version}</span>
                        </div>
                      </td>
                      <td className="td"><VerbChips verbs={s.permissions} /></td>
                      <td className="td text-right">
                        <RowMenu label={s.name} items={[
                          { label: 'Open', onSelect: () => navigate(`/secrets/${seg(s.name)}`) },
                          ...(s.permissions.includes('update') ? [{ label: 'Replace', onSelect: () => navigate(`/secrets/${seg(s.name)}/edit`) }] : []),
                          ...(s.permissions.includes('delete') ? [{ label: 'Delete…', danger: true, onSelect: () => setDeleting(s.name) }] : []),
                        ]} />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          <Pager {...pager} total={all.length} />
        </>
      )}
      <Banner tone="info">
        Secret values are never shown here. A parameter not marked secret can be shown on its secret's page;
        references show where the value lives (<Link2 size={12} className="inline" aria-hidden />), never the value.
      </Banner>
      <ConfirmDelete kind="secret" name={deleting} consequence="DuckDB clients that use it fail their next query."
        onClose={() => setDeleting(null)}
        onConfirm={async () => {
          await api.call('DELETE', `/v1/secrets/${seg(deleting!)}`)
          toast(`${deleting} deleted`)
          setDeleting(null)
          secrets.reload()
        }} />
    </>
  )
}
