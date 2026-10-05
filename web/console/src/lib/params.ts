// The editor's model of a secret's parameters, and what it sends: a PUT's params for a new secret, or the
// console's merge (PATCH /admin/v1/secrets/{name}/params) for a replace - every current parameter kept, set or
// removed, so no value the administrator never saw is lost or shown.
import type { ShapeParam } from './types'

export type Mode = 'keep' | 'value' | 'ref'

export interface Row {
  key: string // a stable id for the list
  name: string
  type: string // DuckDB's
  mode: Mode
  value: string // as typed
  ref: string // the reference built
  secret: boolean // redact_keys
  existing?: ShapeParam // what the secret holds (a replace)
  removed?: boolean
  optional?: boolean // from a template: left empty, it is not sent
  hint?: string // from a template: what the parameter is
}

let next = 0
const key = () => `p${++next}`

/** names a writer usually means secret: the toggle starts on for them */
const secretNames = /(password|passwd|secret|token|client_secret|account_key|access_key|private_key|api_key|session_token|credential|connection_string)/i
export const looksSecret = (name: string) => secretNames.test(name)

export function newRow(name = ''): Row {
  return { key: key(), name, type: 'VARCHAR', mode: 'value', value: '', ref: '', secret: looksSecret(name) }
}

/** a template's rows: its parameters, typed and marked as the extension marks them; the optional ones skipped
 * when left empty */
export function rowsFromTemplate(params: { name: string; type: string; secret: boolean; required: boolean; description: string }[]): Row[] {
  return params.map((p) => ({ ...newRow(p.name), type: p.type, secret: p.secret || looksSecret(p.name), optional: !p.required, hint: p.description }))
}

/** whether the person has typed anything into rows: a template then asks before it replaces them */
export const touched = (rows: Row[]) => rows.some((r) => r.value !== '' || r.ref !== '')

/** the rows of a replace: each current parameter kept as it is */
export function rowsOf(params: ShapeParam[]): Row[] {
  return params.map((p) => ({
    key: key(),
    name: p.name,
    type: p.type,
    mode: 'keep',
    value: text(p.value),
    ref: p.reference ?? '',
    secret: p.redacted,
    existing: p,
  }))
}

/** a stored value as the editor shows it: a bare string, or a typed value's inner value (JSON for nested types) */
export function text(v: unknown): string {
  if (v === undefined || v === null) return ''
  if (typeof v === 'string') return v
  const inner = typeof v === 'object' && 'value' in (v as object) ? (v as { value: unknown }).value : v
  return typeof inner === 'string' ? inner : JSON.stringify(inner)
}

/** a value as the protocol carries it: a bare string for VARCHAR, else {type, value} with the JSON it means */
export function encode(type: string, text: string): unknown {
  const t = type.toUpperCase()
  if (t === 'VARCHAR') return text
  if (/^(TINYINT|SMALLINT|INTEGER|BIGINT|HUGEINT|UTINYINT|USMALLINT|UINTEGER|UBIGINT)$/.test(t)) {
    if (!/^-?\d+$/.test(text.trim())) throw new Error(`a ${t} is a whole number`)
    if (!Number.isSafeInteger(Number(text))) throw new Error('beyond 2^53: set it from DuckDB, where no precision is lost')
    return { type: t, value: Number(text) }
  }
  if (/^(FLOAT|DOUBLE|DECIMAL.*)$/.test(t)) {
    if (text.trim() === '' || Number.isNaN(Number(text))) throw new Error(`a ${t} is a number`)
    if (/^DECIMAL/.test(t) && text.replace(/[^0-9]/g, '').length > 15) throw new Error('more digits than the console keeps: set it from DuckDB')
    return { type: t, value: Number(text) }
  }
  if (t === 'BOOLEAN') {
    if (!/^(true|false)$/i.test(text.trim())) throw new Error('a BOOLEAN is true or false')
    return { type: t, value: text.trim().toLowerCase() === 'true' }
  }
  if (/^(MAP|STRUCT|LIST)|\[\]$/.test(t)) {
    try {
      return { type, value: JSON.parse(text) }
    } catch {
      throw new Error(`a ${type} is written as JSON`)
    }
  }
  return { type, value: text }
}

function valueOf(r: Row): unknown {
  return r.mode === 'ref' ? r.ref : encode(r.type, r.value)
}

/** the problems a form has before it is sent: names, duplicates, empty values */
export function problems(rows: Row[]): Map<string, string> {
  const out = new Map<string, string>()
  const seen = new Set<string>()
  for (const r of rows) {
    if (r.removed) continue
    const name = r.name.trim()
    if (!name) out.set(r.key, 'a parameter needs a name')
    else if (seen.has(name.toLowerCase())) out.set(r.key, `${name} is named twice`)
    seen.add(name.toLowerCase())
    if (r.mode === 'ref' && !r.ref) out.set(r.key, 'complete the reference')
    if (r.mode === 'value' && r.value === '' && r.optional) continue // an optional one left empty: not sent
    // an empty VARCHAR is a value ('' is DuckDB's to judge; a template's "required" is only a hint); an empty secret or
    // another type is a slip
    if (r.mode === 'value' && r.value === '' && (r.secret || r.type.toUpperCase() !== 'VARCHAR')) out.set(r.key, r.existing ? 'a value is needed (keep, or remove the parameter)' : 'a value is needed (or remove the parameter)')
    else if (r.mode === 'value') {
      try {
        valueOf(r)
      } catch (e) {
        out.set(r.key, (e as Error).message)
      }
    }
  }
  return out
}

/** a new secret's params and redact_keys (PUT) */
export function forCreate(rows: Row[]): { params: Record<string, unknown>; redact_keys: string[] } {
  const params: Record<string, unknown> = {}
  const redact: string[] = []
  for (const r of rows) {
    if (r.removed || (r.optional && r.mode === 'value' && r.value === '')) continue
    params[r.name.trim()] = valueOf(r)
    if (r.secret || r.mode === 'ref') redact.push(r.name.trim())
  }
  return { params, redact_keys: redact }
}

/** a replace's merge (PATCH .../params): keep, set, remove - and the marks, a kept secret one always kept */
export function forReplace(rows: Row[]): { keep: string[]; set: Record<string, unknown>; remove: string[]; redact_keys: string[] } {
  const keep: string[] = []
  const set: Record<string, unknown> = {}
  const remove: string[] = []
  const redact: string[] = []
  for (const r of rows) {
    if (r.removed) {
      if (r.existing) remove.push(r.existing.name)
      continue
    }
    if (r.existing && r.mode === 'keep') {
      keep.push(r.existing.name)
      // never unmarked (the service refuses it too); marked now when the toggle says so
      if (r.existing.redacted || r.secret) redact.push(r.existing.name)
      continue
    }
    if (r.existing && r.existing.name !== r.name.trim()) remove.push(r.existing.name) // renamed
    set[r.name.trim()] = valueOf(r)
    if (r.secret || r.mode === 'ref') redact.push(r.name.trim())
  }
  // a name removed and set again (a parameter re-added) is set: the service refuses both
  return { keep, set, remove: remove.filter((k) => !(k in set)), redact_keys: redact }
}

/** an edit carried over onto a newer version of the secret (after a 412): what the person changed stays */
export function rebase(params: ShapeParam[], rows: Row[]): Row[] {
  const fresh = rowsOf(params)
  const byName = new Map(fresh.map((r) => [r.name, r]))
  const added: Row[] = []
  for (const r of rows) {
    const name = r.existing?.name ?? r.name.trim()
    const target = byName.get(name)
    if (!r.existing) {
      if (target) Object.assign(target, { mode: r.mode, value: r.value, ref: r.ref, secret: r.secret || target.secret, type: r.type })
      else added.push(r)
    } else if (target && (r.removed || r.mode !== 'keep' || r.secret !== r.existing.redacted)) {
      Object.assign(target, { mode: r.mode, value: r.mode === 'keep' ? target.value : r.value, ref: r.ref, removed: r.removed, secret: r.secret || target.secret })
    }
  }
  return [...fresh, ...added]
}
