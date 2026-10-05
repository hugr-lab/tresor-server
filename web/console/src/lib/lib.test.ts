import { describe, expect, it } from 'vitest'
import { encode, forCreate, forReplace, newRow, problems, rowsOf, looksSecret } from './params'
import { buildRef, parseRef, allowed } from './refs'
import { sqlPreview } from './sql'
import { ago } from './time'
import type { Source } from './types'

const vault: Source = { name: 'vault-us', kind: 'vault', named: true, connection: '', allow: ['secret/duckdb/*'], cache_ttl: '0s' }
const azkv: Source = { name: 'azkv', kind: 'azkv', named: false, connection: '', allow: ['corp-kv/duckdb-*'], cache_ttl: '0s' }

describe('params', () => {
  it('encodes values as the protocol carries them', () => {
    expect(encode('VARCHAR', 'x')).toBe('x')
    expect(encode('INTEGER', '5432')).toEqual({ type: 'INTEGER', value: 5432 })
    expect(encode('BOOLEAN', 'True')).toEqual({ type: 'BOOLEAN', value: true })
    expect(encode('MAP(VARCHAR, VARCHAR)', '{"a":"b"}')).toEqual({ type: 'MAP(VARCHAR, VARCHAR)', value: { a: 'b' } })
    expect(() => encode('INTEGER', '5.5')).toThrow()
    expect(() => encode('MAP(VARCHAR, VARCHAR)', '{a')).toThrow()
  })

  it('marks secret-looking names', () => {
    expect(looksSecret('password')).toBe(true)
    expect(looksSecret('client_secret')).toBe(true)
    expect(looksSecret('host')).toBe(false)
    expect(newRow('api_key').secret).toBe(true)
  })

  it('builds a new secret', () => {
    const host = { ...newRow('host'), value: 'db' }
    const pw = { ...newRow('password'), mode: 'ref' as const, ref: 'ref+vault://secret/duckdb/pg#pw' }
    expect(forCreate([host, pw])).toEqual({ params: { host: 'db', password: 'ref+vault://secret/duckdb/pg#pw' }, redact_keys: ['password'] })
  })

  it('replaces keeping what it never saw, and never unmarks a kept secret', () => {
    const rows = rowsOf([
      { name: 'host', type: 'VARCHAR', redacted: false, value: 'db' },
      { name: 'password', type: 'VARCHAR', redacted: true },
      { name: 'sslmode', type: 'VARCHAR', redacted: false },
    ])
    rows[0] = { ...rows[0], mode: 'value', value: 'db2' }
    rows[1] = { ...rows[1], secret: false } // the toggle flipped on a kept secret
    rows[2] = { ...rows[2], removed: true }
    const added = { ...newRow('port'), type: 'INTEGER', value: '5433' }
    expect(forReplace([...rows, added])).toEqual({
      keep: ['password'],
      set: { host: 'db2', port: { type: 'INTEGER', value: 5433 } },
      remove: ['sslmode'],
      redact_keys: ['password'],
    })
  })

  it('finds problems before sending', () => {
    const a = { ...newRow('x'), value: '1' }
    const b = { ...newRow('X'), value: '2' }
    const c = { ...newRow(''), value: '3' }
    const d = { ...newRow('n'), type: 'INTEGER', value: 'many' }
    const p = problems([a, b, c, d])
    expect(p.get(b.key)).toMatch(/twice/)
    expect(p.get(c.key)).toMatch(/name/)
    expect(p.get(d.key)).toMatch(/whole number/)
    expect(p.has(a.key)).toBe(false)
  })
})

describe('references', () => {
  it('builds and parses each kind', () => {
    const v = { source: 'vault-us', a: 'secret', b: 'duckdb/lake', c: 'key' }
    expect(buildRef('vault', v)).toBe('ref+vault-us://secret/duckdb/lake#key')
    expect(parseRef('ref+vault-us://secret/duckdb/lake#key', [vault])).toEqual(v)
    expect(buildRef('azkv', { source: 'azkv', a: 'corp-kv', b: 'duckdb-s3', c: '' })).toBe('ref+azkv://corp-kv/duckdb-s3')
    expect(parseRef('ref+nope://x/y', [vault])).toBeUndefined()
  })
  it('hints the allowlist', () => {
    expect(allowed(vault, { source: 'vault-us', a: 'secret', b: 'duckdb/x', c: 'f' })).toBe(true)
    expect(allowed(vault, { source: 'vault-us', a: 'secret', b: 'finance/x', c: 'f' })).toBe(false)
    expect(allowed(azkv, { source: 'azkv', a: 'CORP-KV', b: 'DuckDB-s3', c: '' })).toBe(true)
  })
})

describe('sql', () => {
  it('masks secret values and shows references', () => {
    const rows = rowsOf([
      { name: 'host', type: 'VARCHAR', redacted: false, value: 'db' },
      { name: 'password', type: 'VARCHAR', redacted: true },
      { name: 'dsn', type: 'VARCHAR', redacted: true, reference: 'ref+vault://secret/duckdb/pg#dsn' },
    ])
    const sql = sqlPreview('pg', 'postgres', 'config', ["postgres://db"], rows)
    expect(sql).toContain("HOST 'db'  -- kept")
    expect(sql).toContain("PASSWORD '••••'  -- kept, secret")
    expect(sql).toContain("DSN 'ref+vault://secret/duckdb/pg#dsn'")
    expect(sql).not.toContain('PROVIDER')
  })
})

describe('time', () => {
  it('reads as people do', () => {
    const now = Date.parse('2026-10-05T12:00:00Z')
    expect(ago('2026-10-05T11:59:30Z', now)).toBe('just now')
    expect(ago('2026-10-05T10:00:00Z', now)).toBe('2 h ago')
    expect(ago('2026-10-04T10:00:00Z', now)).toBe('yesterday')
  })
})
