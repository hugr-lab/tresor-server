// The statement a secret amounts to, as the console shows it: values masked, references as written.
import type { Row } from './params'

const q = (s: string) => `'${s.replace(/'/g, "''")}'`
/** an identifier as DuckDB reads it: bare when plain, else double-quoted */
export const ident = (s: string) => (/^[A-Za-z_][A-Za-z0-9_]*$/.test(s) ? s : `"${s.replace(/"/g, '""')}"`)

export function sqlPreview(name: string, type: string, provider: string, scope: string[], rows: Row[]): string {
  const lines = [`    TYPE ${type || '<type>'}`]
  if (provider && provider !== 'config') lines.push(`    PROVIDER ${provider}`)
  for (const r of rows) {
    if (r.removed || !r.name.trim()) continue
    if (r.mode === 'value' && r.value === '' && r.optional) continue // an optional one left empty is not sent
    const key = ident(r.name.trim()).toUpperCase()
    let v: string
    if (r.mode === 'ref') v = q(r.ref || 'ref+…')
    else if (r.mode === 'keep') v = r.existing?.reference ? q(r.existing.reference) : r.secret ? "'••••'  -- kept, secret" : `${shown(r)}  -- kept`
    else v = r.secret ? "'••••'" : shown(r)
    lines.push(`    ${key} ${v}`)
  }
  if (scope.length) lines.push(`    SCOPE [${scope.map(q).join(', ')}]`)
  return `CREATE OR REPLACE PERSISTENT SECRET ${name ? ident(name) : '<name>'} IN tresor (\n${lines.join(',\n')}\n);`
}

function shown(r: Row): string {
  if (r.value === '') return "''"
  const t = r.type.toUpperCase()
  if (t === 'VARCHAR') return q(r.value)
  if (/^(MAP|STRUCT|LIST)|\[\]$/.test(t)) {
    try {
      return literal(JSON.parse(r.value), /^MAP/.test(t))
    } catch {
      return q(r.value)
    }
  }
  return r.value
}

/** a nested value as a DuckDB literal: MAP {'k': 'v'}, a struct {'k': v}, a list [v, ...] */
function literal(v: unknown, map = false): string {
  if (Array.isArray(v)) return `[${v.map((x) => literal(x)).join(', ')}]`
  if (v && typeof v === 'object') {
    const body = Object.entries(v).map(([k, x]) => `${q(k)}: ${literal(x)}`).join(', ')
    return map ? `MAP {${body}}` : `{${body}}`
  }
  if (typeof v === 'string') return q(v)
  return v === null ? 'NULL' : String(v)
}
