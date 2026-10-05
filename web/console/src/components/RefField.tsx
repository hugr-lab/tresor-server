// A reference built from its parts: a configured source, then the place its kind takes - with the source's
// allowlist as a hint (the service decides, and says why at the save).
import { useEffect, useState } from 'react'
import { Link2 } from 'lucide-react'
import { allowed, buildRef, parseRef, refLabels, type RefParts } from '../lib/refs'
import type { Source } from '../lib/types'

export function RefField({ sources, value, onChange, label }: { sources: Source[]; value: string; onChange: (ref: string) => void; label: string }) {
  const [parts, setParts] = useState<RefParts>(() => parseRef(value, sources) ?? { source: sources[0]?.name ?? '', a: '', b: '', c: '' })
  const src = sources.find((s) => s.name === parts.source)
  const kind = src?.kind ?? 'vault'
  const complete = !!parts.source && !!parts.a && !!parts.b && (kind === 'azkv' || !!parts.c)
  const ref = complete ? buildRef(kind, parts) : ''
  useEffect(() => {
    if (ref !== value) onChange(ref)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ref])
  if (!sources.length) {
    return <span className="text-[13px] text-muted">No reference source is configured (material: in the service's configuration).</span>
  }
  const [la, lb, lc] = refLabels[kind] ?? refLabels.vault
  const set = (k: keyof RefParts) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setParts({ ...parts, [k]: e.target.value })
  return (
    <div className="flex w-full flex-col gap-2 rounded-md border border-line p-3" role="group" aria-label={`${label}: reference`}>
      <div className="grid grid-cols-4 gap-2">
        <label className="flex flex-col gap-1 text-[12px] font-semibold">Source
          <select className="input py-1.5 font-mono text-[13px]" value={parts.source} onChange={set('source')}>
            {sources.map((s) => <option key={s.name} value={s.name}>{s.name}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-[12px] font-semibold">{la}<input className="input py-1.5 font-mono text-[13px]" value={parts.a} onChange={set('a')} /></label>
        <label className="flex flex-col gap-1 text-[12px] font-semibold">{lb}<input className="input py-1.5 font-mono text-[13px]" value={parts.b} onChange={set('b')} /></label>
        <label className="flex flex-col gap-1 text-[12px] font-semibold">{lc}<input className="input py-1.5 font-mono text-[13px]" value={parts.c} onChange={set('c')} /></label>
      </div>
      <div className="flex flex-wrap items-center gap-2 text-[12px]">
        <Link2 size={15} className="text-brand" aria-hidden />
        <span className="break-all font-mono text-[13px]">{ref || 'ref+…'}</span>
        {src && (
          <span className={`ml-auto ${complete && !allowed(src, parts) ? 'text-danger' : 'text-muted'}`}>
            {complete && !allowed(src, parts) ? 'Outside what the source may read: ' : 'May read: '}
            <span className="font-mono">{src.allow.join(', ')}</span>
          </span>
        )}
      </div>
    </div>
  )
}
