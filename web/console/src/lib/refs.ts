// References (ref+<source>://...) as the editor builds them: the parts each kind of source takes, and back.
import type { Source } from './types'

export interface RefParts {
  source: string // a configured source's name
  a: string // vault: mount; azkv: vault; k8s: namespace
  b: string // vault: path; azkv: secret; k8s: Secret
  c: string // vault: field; azkv: version (optional); k8s: key
}

export const refLabels: Record<string, [string, string, string]> = {
  vault: ['Mount', 'Path', 'Field'],
  azkv: ['Vault', 'Secret', 'Version (optional)'],
  k8s: ['Namespace', 'Secret', 'Key'],
}

export function buildRef(kind: string, p: RefParts): string {
  switch (kind) {
    case 'vault':
      return `ref+${p.source}://${p.a}/${p.b}#${p.c}`
    case 'azkv':
      return `ref+${p.source}://${p.a}/${p.b}${p.c ? '/' + p.c : ''}`
    default:
      return `ref+${p.source}://${p.a}/${p.b}/${p.c}`
  }
}

/** the parts of a reference, given the configured sources; undefined for one no source has */
export function parseRef(text: string, sources: Source[]): RefParts | undefined {
  const m = /^ref\+([a-z][a-z0-9-]*):\/\/(.*)$/.exec(text)
  if (!m) return undefined
  const src = sources.find((s) => s.name === m[1])
  if (!src) return undefined
  const rest = m[2]
  if (src.kind === 'vault') {
    const [where, field = ''] = rest.split('#')
    const i = where.indexOf('/')
    return i < 0 ? { source: src.name, a: where, b: '', c: field } : { source: src.name, a: where.slice(0, i), b: where.slice(i + 1), c: field }
  }
  const parts = rest.split('/')
  return { source: src.name, a: parts[0] ?? '', b: parts[1] ?? '', c: parts[2] ?? '' }
}

/** whether a place is within the source's allowlist, as the hint shows it (the service decides) */
export function allowed(src: Source, p: RefParts): boolean {
  const place = `${p.a}/${p.b}`
  return src.allow.some((rule) => {
    const prefix = rule.endsWith('*') ? rule.slice(0, -1) : rule
    return src.kind === 'azkv' ? place.toLowerCase().startsWith(prefix.toLowerCase()) : place.startsWith(prefix)
  })
}
