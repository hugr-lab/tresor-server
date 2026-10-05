// Every package the console ships (dependencies, not the tools that build it) is under a permissive licence:
// no licence that binds the users of the build, nothing unknown. Run in CI (npm run licenses).
import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const allowed = new Set(['MIT', 'ISC', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', '0BSD', 'OFL-1.1'])
const lock = JSON.parse(readFileSync('package-lock.json', 'utf8'))
const bad = []
for (const [path, pkg] of Object.entries(lock.packages)) {
  if (!path || pkg.dev) continue // the root, and build tools
  const manifest = join(path, 'package.json')
  const license = pkg.license ?? (existsSync(manifest) ? JSON.parse(readFileSync(manifest, 'utf8')).license : undefined)
  const ids = String(license ?? 'UNKNOWN').replace(/[()]/g, '').split(/\s+OR\s+/)
  if (!ids.some((id) => allowed.has(id.trim()))) bad.push(`${path}: ${license}`)
}
if (bad.length) {
  console.error('licences not allowed:\n' + bad.join('\n'))
  process.exit(1)
}
console.log('licences: every shipped package is permissive')
