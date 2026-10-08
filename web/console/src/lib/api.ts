// The service's API: the protocol's routes (/v1) and the console's own (/admin/v1), with the administrator's
// bearer token. An answer that is not 2xx is an ApiError carrying the problem document (RFC 9457).
import type { Problem } from './types'

export class ApiError extends Error {
  constructor(public readonly problem: Problem) {
    super(problem.detail || problem.title)
  }
  get status() {
    return this.problem.status
  }
  get type() {
    return this.problem.type
  }
}

export interface Answer<T> {
  data: T
  etag: string | null
}

/** what the API tells its owner about the token (spec 016): refused even renewed, or accepted again */
export interface TokenEvents {
  unauthorized?: () => void
  authorized?: () => void
}

export class Api {
  private renewing?: Promise<string> // one renewal for every request refused meanwhile: a refresh token is used once
  private refusals = 0 // how many times the session was refused: an answer to an older request does not clear it

  constructor(
    private readonly base: string,
    // renew: the host's token was refused - a fresh one, not its cache's (spec 016)
    private readonly token: (renew?: boolean) => Promise<string>,
    private readonly events: TokenEvents = {},
  ) {}

  private renewed(): Promise<string> {
    if (!this.renewing) {
      const p = this.token(true).finally(() => {
        if (this.renewing === p) this.renewing = undefined
      })
      this.renewing = p
    }
    return this.renewing
  }

  async call<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<Answer<T>> {
    const payload = body === undefined ? undefined : JSON.stringify(body)
    let refusals = this.refusals
    const send = async (renew: boolean) => {
      const h: Record<string, string> = { Authorization: `Bearer ${await (renew ? this.renewed() : this.token(false))}`, ...headers }
      if (payload !== undefined) h['Content-Type'] = 'application/json'
      try {
        return await fetch(this.base.replace(/\/$/, '') + path, { method, headers: h, body: payload, cache: 'no-store', credentials: 'omit' })
      } catch {
        throw new ApiError({ type: 'service_unavailable', title: 'service_unavailable', status: 0, detail: 'the service did not answer' })
      }
    }
    let res = await send(false)
    if (res.status === 401) {
      await res.body?.cancel().catch(() => undefined)
      refusals = this.refusals
      res = await send(true) // the token expired on the way, or was revoked: once more with a renewed one
      if (res.status === 401) {
        this.refusals++
        this.events.unauthorized?.()
      }
    }
    if (res.status !== 401 && refusals === this.refusals) this.events.authorized?.()
    const etag = res.headers.get('ETag')
    if (res.status === 204) return { data: undefined as T, etag }
    const text = await res.text()
    let parsed: unknown
    try {
      parsed = text ? JSON.parse(text) : undefined
    } catch {
      parsed = undefined
    }
    if (!res.ok) {
      const p = (parsed ?? {}) as Partial<Problem>
      throw new ApiError({ type: p.type ?? 'service_error', title: p.title ?? String(res.status), status: res.status, detail: p.detail ?? res.statusText })
    }
    return { data: parsed as T, etag }
  }

  get<T>(path: string) {
    return this.call<T>('GET', path)
  }
}

/** a name in an API path: the protocol's names are any UTF-8 text */
export const seg = (name: string) => encodeURIComponent(name)

/** a name in the console's own routes: encoded twice, since the router decodes a parameter once (%2F stays a
 * name's character, never a path separator) */
export const route = (name: string) => encodeURIComponent(encodeURIComponent(name))

/** a route parameter back to the name */
export const nameOf = (param: string | undefined) => (param === undefined ? '' : decodeURIComponent(param))
