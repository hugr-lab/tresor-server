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
}

let next = 0
const key = () => `p${++next}`

/** names a writer usually means secret: the toggle starts on for them */
const secretNames = /(password|passwd|secret|token|client_secret|account_key|access_key|private_key|api_key|session_token|credential|connection_string)/i
export const looksSecret = (name: string) => secretNames.test(name)

export function newRow(name = ''): Row {
  return { key: key(), name, type: 'VARCHAR', mode: 'value', value: '', ref: '', secret: looksSecret(name) }
}

/** the rows of a replace: each current parameter kept as it is */
export function rowsOf(params: ShapeParam[]): Row[] {
  return params.map((p) => ({
    key: key(),
    name: p.name,
    type: p.type,
    mode: 'keep',
    value: p.value === undefined ? '' : typeof p.value === 'string' ? p.value : JSON.stringify(p.value),
    ref: p.reference ?? '',
    secret: p.redacted,
    existing: p,
  }))
}

/** a value as the protocol carries it: a bare string for VARCHAR, else {type, value} with the JSON it means */
export function encode(type: string, text: string): unknown {
  const t = type.toUpperCase()
  if (t === 'VARCHAR') return text
  if (/^(TINYINT|SMALLINT|INTEGER|BIGINT|HUGEINT|UTINYINT|USMALLINT|UINTEGER|UBIGINT)$/.test(t)) {
    if (!/^-?\d+$/.test(text.trim())) throw new Error(`a ${t} is a whole number`)
    return { type: t, value: Number(text) }
  }
  if (/^(FLOAT|DOUBLE|DECIMAL.*)$/.test(t)) {
    if (text.trim() === '' || Number.isNaN(Number(text))) throw new Error(`a ${t} is a number`)
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
    if (r.mode === 'value') {
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
    if (r.removed) continue
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
      if (r.existing.redacted) redact.push(r.existing.name) // never unmarked: the service refuses it too
      continue
    }
    if (r.existing && r.existing.name !== r.name.trim()) remove.push(r.existing.name) // renamed
    set[r.name.trim()] = valueOf(r)
    if (r.secret || r.mode === 'ref') redact.push(r.name.trim())
  }
  return { keep, set, remove, redact_keys: redact }
}
