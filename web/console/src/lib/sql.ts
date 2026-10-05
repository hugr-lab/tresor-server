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
  if (r.value === '') return "'••••'"
  return r.type.toUpperCase() === 'VARCHAR' ? q(r.value) : r.value
}
