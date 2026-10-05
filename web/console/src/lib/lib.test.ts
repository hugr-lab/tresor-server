import { describe, expect, it } from 'vitest'
import { encode, forCreate, forReplace, newRow, problems, rowsOf, looksSecret, rebase, rowsFromTemplate } from './params'
import { grantId, idFor } from './grants'
import { buildRef, parseRef, allowed } from './refs'
import { ident, sqlPreview } from './sql'
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

describe('the review of (010 b)', () => {
  it('marks a kept parameter secret when the toggle says so', () => {
    const rows = rowsOf([{ name: 'token', type: 'VARCHAR', redacted: false, value: 'x' }])
    rows[0] = { ...rows[0], secret: true }
    expect(forReplace(rows).redact_keys).toEqual(['token'])
  })
  it('unwraps typed values, and refuses empty ones and big integers', () => {
    const rows = rowsOf([
      { name: 'port', type: 'INTEGER', redacted: false, value: { type: 'INTEGER', value: 5432 } },
      { name: 'h', type: 'MAP(VARCHAR, VARCHAR)', redacted: false, value: { type: 'MAP(VARCHAR, VARCHAR)', value: { a: 'b' } } },
    ])
    expect(rows[0].value).toBe('5432')
    expect(rows[1].value).toBe('{"a":"b"}')
    const pw = { ...rowsOf([{ name: 'password', type: 'VARCHAR', redacted: true }])[0], mode: 'value' as const, value: '' }
    expect(problems([pw]).get(pw.key)).toMatch(/value is needed/)
    expect(() => encode('BIGINT', '9007199254740993')).toThrow(/2\^53/)
  })
  it('sets a removed name again instead of removing it', () => {
    const rows = rowsOf([{ name: 'host', type: 'VARCHAR', redacted: false, value: 'a' }])
    rows[0] = { ...rows[0], removed: true }
    const again = { ...newRow('host'), value: 'b' }
    expect(forReplace([...rows, again])).toMatchObject({ remove: [], set: { host: 'b' } })
  })
  it('carries an edit over onto a newer version', () => {
    const mine = rowsOf([{ name: 'host', type: 'VARCHAR', redacted: false, value: 'a' }, { name: 'pw', type: 'VARCHAR', redacted: true }])
    mine[0] = { ...mine[0], mode: 'value', value: 'mine' }
    const added = { ...newRow('port'), type: 'INTEGER', value: '1' }
    const rebased = rebase([{ name: 'host', type: 'VARCHAR', redacted: false, value: 'theirs' }, { name: 'pw', type: 'VARCHAR', redacted: true }, { name: 'db', type: 'VARCHAR', redacted: false }], [...mine, added])
    expect(rebased.map((r) => [r.name, r.mode, r.value])).toEqual([['host', 'value', 'mine'], ['pw', 'keep', ''], ['db', 'keep', ''], ['port', 'value', '1']])
  })
  it('computes tresor\'s grant ids', () => {
    expect(grantId('role:analysts')).toMatch(/^g-[0-9a-f]{16}$/)
    expect(grantId('role:a/b')).not.toBe(grantId('role:a:b'))
    expect(idFor([{ id: 'mine', principal: 'role:x', verbs: ['use'] }], 'role:x')).toBe('mine')
  })
  it('quotes odd names in SQL', () => {
    expect(ident('lake_s3')).toBe('lake_s3')
    expect(ident('my secret')).toBe('"my secret"')
  })
})

describe('templates', () => {
  it('skips an optional parameter left empty, and sends an empty VARCHAR but not an empty secret', () => {
    const rows = rowsFromTemplate([
      { name: 'key_id', type: 'VARCHAR', secret: false, required: true, description: '' },
      { name: 'secret', type: 'VARCHAR', secret: true, required: true, description: '' },
      { name: 'region', type: 'VARCHAR', secret: false, required: false, description: '' },
    ])
    expect(rows[1].secret).toBe(true)
    expect([...problems(rows).keys()]).toEqual([rows[1].key])
    expect(forCreate([rows[0]]).params).toEqual({ key_id: '' })
    rows[0].value = 'AKIA'
    rows[1].value = 's'
    expect(problems(rows).size).toBe(0)
    expect(forCreate(rows)).toEqual({ params: { key_id: 'AKIA', secret: 's' }, redact_keys: ['secret'] })
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

describe('sqlPreview', () => {
  it('writes a MAP as a DuckDB literal and skips an empty optional one', () => {
    const map = { ...newRow('metadata_parameters'), type: 'MAP(VARCHAR, VARCHAR)', secret: false, value: JSON.stringify({ TYPE: 'postgres', user: "o'k" }) }
    const opt = { ...newRow('data_path'), secret: false, optional: true }
    const sql = sqlPreview('lake', 'ducklake', 'config', [], [map, opt])
    expect(sql).toContain("METADATA_PARAMETERS MAP {'TYPE': 'postgres', 'user': 'o''k'}")
    expect(sql).not.toContain('DATA_PATH')
  })
})
