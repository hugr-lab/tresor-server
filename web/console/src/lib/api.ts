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

export class Api {
  constructor(
    private readonly base: string,
    private readonly token: () => Promise<string>,
  ) {}

  async call<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<Answer<T>> {
    const h: Record<string, string> = { Authorization: `Bearer ${await this.token()}`, ...headers }
    if (body !== undefined) h['Content-Type'] = 'application/json'
    let res: Response
    try {
      res = await fetch(this.base.replace(/\/$/, '') + path, {
        method,
        headers: h,
        body: body === undefined ? undefined : JSON.stringify(body),
        cache: 'no-store',
        credentials: 'omit',
      })
    } catch {
      throw new ApiError({ type: 'service_unavailable', title: 'service_unavailable', status: 0, detail: 'the service did not answer' })
    }
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
