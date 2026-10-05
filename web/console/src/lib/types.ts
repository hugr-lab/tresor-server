// The shapes the console reads: the protocol's (duckdb-secrets/1) and the console's own (/admin/v1, spec 010).

export type Verb = 'use' | 'update' | 'delete' | 'annotate' | 'grant'

export interface Descriptor {
  name: string
  type: string
  provider: string
  scope: string[]
  comment: string
  owner: string
  created_at: string
  updated_at: string
  version: string
  dynamic: boolean
  permissions: Verb[]
}

export interface VariableDescriptor {
  name: string
  comment: string
  owner: string
  created_at: string
  updated_at: string
  version: string
  sensitive: boolean
  permissions: Verb[]
}

export interface Grant {
  id: string
  principal: string
  verbs: string[]
}

export interface ShapeParam {
  name: string
  type: string
  redacted: boolean
  reference?: string
  value?: unknown // only asked for (values=1), only for a parameter neither secret nor a reference
}

export interface Shape {
  name: string
  kind: 'secret' | 'variable'
  version: string
  type?: string
  provider?: string
  params: ShapeParam[]
}

export interface Source {
  name: string
  kind: 'vault' | 'azkv' | 'k8s' | string
  named: boolean
  connection: string
  allow: string[]
  cache_ttl: string
}

export interface ServiceInfo {
  version: string
  protocol: string
  environment: string
  capabilities: string[]
  state: string
  kek: { kind: string; current?: string; error?: string }
  issuers: { issuer: string; audience: string; client_id?: string; exchange?: { client_id: string; client_auth: string } }[]
  sources: Source[]
  policy: { admins: string[]; actors: { principal: string; verbs: string[] }[] }
  audit: string
  ready: { ready: boolean; checks: Record<string, string> }
}

export interface Whoami {
  issuer: string
  subject: string
  roles: string[]
  actor: string | null
  expires_at: string
  permissions: { create: boolean | string[] }
}

export interface Finding {
  kind: 'secret' | 'variable'
  name: string
  param: string
  reason: string
}

export interface Problem {
  type: string
  title: string
  status: number
  detail: string
}
