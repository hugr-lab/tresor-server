// Grant ids as tresor computes them (tresor_manage.cpp GrantId): FNV-1a 64 over the principal's UTF-8 bytes,
// "g-" and 16 hex digits - so a grant made here and one made from SQL are the same grant. A principal that
// already holds a grant keeps its id.
import type { Grant } from './types'

export function grantId(principal: string): string {
  let hash = 14695981039346656037n
  for (const byte of new TextEncoder().encode(principal)) {
    hash ^= BigInt(byte)
    hash = (hash * 1099511628211n) & 0xffffffffffffffffn
  }
  return `g-${hash.toString(16).padStart(16, '0')}`
}

/** the id to grant principal with: its existing grant's, else tresor's */
export function idFor(existing: Grant[], principal: string): string {
  return existing.find((g) => g.principal === principal)?.id ?? grantId(principal)
}
