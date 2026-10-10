// Paths within the console: where a sign-in returns to (an open redirect closed: GHSA-wrjc-x8rr-h8h6), and what the
// microfrontend takes from its host's address. No dependency: the microfrontend's bundle imports it.

/** the page a sign-in starts from, within the console (below its base), with its query: where it returns */
export function here(): string {
  const base = new URL(document.baseURI).pathname.replace(/\/$/, '')
  const path = window.location.pathname.startsWith(base) ? window.location.pathname.slice(base.length) : ''
  return (path || '/secrets') + window.location.search
}

/** a path within the console to go back to after a sign-in, or undefined: one slash first, then neither a slash
 * nor a backslash - '//host' would leave the origin, and a browser reads a backslash as a slash - and no
 * backslash or control character anywhere. The second line is the router's: it collapses repeated slashes when it
 * joins a path to the base, but where pushState fails it falls back to location.assign. */
export function localPath(p: string | undefined): string | undefined {
  if (!p || !p.startsWith('/') || p.startsWith('//') || p.startsWith('/\\')) return undefined
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(p)) return undefined
  return p
}
