// A secret's type: the types DuckDB's extensions register (with their extension and what they are for), and the
// ones this service already holds - or any other, typed. A combobox: arrows, Enter, Escape.
import { useMemo, useRef, useState } from 'react'
import { ChevronDown } from 'lucide-react'
import { templates } from '../lib/templates'

interface Option {
  type: string
  group: string
  description: string
}

export function TypePicker({ value, onChange, inUse, disabled }: { value: string; onChange: (t: string) => void; inUse: string[]; disabled?: boolean }) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const input = useRef<HTMLInputElement>(null)
  const options = useMemo<Option[]>(() => {
    const known = new Set(templates.map((t) => t.type.toLowerCase()))
    const used = [...new Set(inUse.map((t) => t.toLowerCase()))].filter((t) => !known.has(t)).sort()
    const all: Option[] = [
      ...templates.map((t) => ({ type: t.type, group: `${t.extension}${inUse.some((u) => u.toLowerCase() === t.type.toLowerCase()) ? ' · in use' : ''}`, description: t.description })),
      ...used.map((t) => ({ type: t, group: 'in use here', description: 'held by this service; no template' })),
    ]
    const q = query.trim().toLowerCase()
    return all.filter((o) => !q || `${o.type} ${o.group} ${o.description}`.toLowerCase().includes(q))
  }, [inUse, query])
  const pick = (t: string) => {
    onChange(t)
    setQuery('')
    setOpen(false)
  }
  return (
    <div className="relative">
      <div className="flex items-center rounded-sm border border-line bg-surface">
        <input ref={input} role="combobox" aria-expanded={open} aria-controls="type-options" aria-autocomplete="list" disabled={disabled}
          className="min-w-0 flex-1 rounded-sm border-0 bg-transparent px-3 py-2 font-mono text-ink outline-none"
          value={open ? query : value}
          placeholder={value ? `${value} — type to search` : 's3, postgres, ducklake…'}
          onFocus={() => { setQuery(''); setOpen(true); setActive(0) }}
          onBlur={() => setTimeout(() => setOpen(false), 120)}
          onChange={(e) => { setQuery(e.target.value); setActive(0); setOpen(true) }}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(a + 1, options.length - 1)) }
            else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)) }
            else if (e.key === 'Enter') { e.preventDefault(); pick(options[active]?.type ?? query.trim()) }
            else if (e.key === 'Escape') { setOpen(false); input.current?.blur() }
          }} />
        {!disabled && <ChevronDown size={16} className="mr-2 text-muted" aria-hidden />}
      </div>
      {open && !disabled && (
        <ul id="type-options" role="listbox" className="absolute left-0 top-full z-30 w-full min-w-[440px] mt-1 max-h-[320px] overflow-y-auto rounded-md border border-line bg-surface p-1.5">
          {options.map((o, i) => (
            <li key={o.type} role="option" aria-selected={i === active} onMouseDown={(e) => { e.preventDefault(); pick(o.type) }} onMouseEnter={() => setActive(i)}
              className={`flex cursor-pointer flex-col rounded-[10px] px-3 py-1.5 ${i === active ? 'bg-soft' : ''}`}>
              <span className="flex items-baseline gap-2">
                <span className="font-mono text-[13px] font-medium">{o.type}</span>
                <span className="text-[11px] uppercase tracking-[0.04em] text-muted">{o.group}</span>
              </span>
              <span className="text-[12px] text-muted">{o.description}</span>
            </li>
          ))}
          {query.trim() && !options.some((o) => o.type.toLowerCase() === query.trim().toLowerCase()) && (
            <li role="option" aria-selected={false} onMouseDown={(e) => { e.preventDefault(); pick(query.trim()) }} className="cursor-pointer rounded-[10px] px-3 py-1.5 text-[13px] text-muted hover:bg-soft">
              Use <span className="font-mono text-ink">{query.trim()}</span> (no template)
            </li>
          )}
        </ul>
      )}
    </div>
  )
}
