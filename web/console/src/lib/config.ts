// What the service tells the console before sign-in: /ui/config.json (spec 010).

export interface IssuerConfig {
  issuer: string
  client_id: string
  scopes?: string[]
  audience: string
  audience_parameter?: boolean
}

export interface ConsoleConfig {
  api: string // public_url
  issuers: IssuerConfig[]
  environment: string
}

export async function loadConfig(): Promise<ConsoleConfig> {
  const res = await fetch(new URL('config.json', document.baseURI), { cache: 'no-store' })
  if (!res.ok) throw new Error(`config.json: ${res.status}`)
  return (await res.json()) as ConsoleConfig
}
