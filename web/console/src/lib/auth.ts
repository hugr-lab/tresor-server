// Sign-in (spec 010): OIDC Authorization Code + PKCE against an issuer's public client. The access token stays in
// memory - never in localStorage - and only the PKCE state rides in sessionStorage across the redirect. A reload
// signs in again through the IdP's own session, without a prompt when it has one. Renewal is by a refresh token,
// never in a hidden frame (the page's CSP has no frame-src).
import { InMemoryWebStorage, UserManager, WebStorageStateStore, type User } from 'oidc-client-ts'
import type { IssuerConfig } from './config'

const lastIssuer = 'tresor.issuer' // which issuer this tab signed in with: a URL, no secret
const popupName = 'tresor-signin' // the window a sign-in again opens in

export class Session {
  private managers = new Map<string, UserManager>()
  private user: User | null = null
  private listeners = new Set<() => void>()
  private completing?: Promise<string | undefined> // a callback runs once, however often it is asked

  constructor(private issuers: IssuerConfig[]) {}

  private manager(issuer: IssuerConfig): UserManager {
    let m = this.managers.get(issuer.issuer)
    if (!m) {
      m = new UserManager({
        authority: issuer.issuer,
        client_id: issuer.client_id,
        redirect_uri: new URL('callback', document.baseURI).href,
        response_type: 'code',
        scope: (issuer.scopes?.length ? issuer.scopes : ['openid']).join(' '),
        extraQueryParams: issuer.audience_parameter ? { audience: issuer.audience } : undefined,
        userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
        stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
        popup_redirect_uri: new URL('callback', document.baseURI).href,
        popupWindowTarget: popupName,
        post_logout_redirect_uri: new URL('./', document.baseURI).href,
        automaticSilentRenew: true, // with a refresh token; without one the session ends and the page asks again
        monitorSession: false,
        loadUserInfo: false,
      })
      m.events.addUserLoaded((u) => this.set(u))
      m.events.addAccessTokenExpired(() => this.set(null))
      m.events.addSilentRenewError(() => this.notify())
      this.managers.set(issuer.issuer, m)
    }
    return m
  }

  private set(u: User | null) {
    this.user = u
    this.notify()
  }

  private notify() {
    this.listeners.forEach((l) => l())
  }

  subscribe(l: () => void): () => void {
    this.listeners.add(l)
    return () => this.listeners.delete(l)
  }

  get signedIn(): boolean {
    return !!this.user && !this.user.expired
  }

  /** a name to show: the ID token's name or user name, else nothing */
  get displayName(): string | undefined {
    const p = this.user?.profile
    return (p?.name || p?.preferred_username || p?.email) as string | undefined
  }

  get expiresAt(): number | undefined {
    return this.user?.expires_at
  }

  /** the issuer this tab used last, to sign in again after a reload */
  remembered(): IssuerConfig | undefined {
    const url = sessionStorage.getItem(lastIssuer)
    return this.issuers.find((i) => i.issuer === url)
  }

  async signIn(issuer: IssuerConfig, returnTo: string): Promise<void> {
    sessionStorage.setItem(lastIssuer, issuer.issuer)
    await this.manager(issuer).signinRedirect({ state: { returnTo: localPath(returnTo) ?? '/secrets' } })
  }

  /** completes a sign-in: a redirect's (the path to go back to), or a popup's (undefined: the window closes) */
  callback(): Promise<string | undefined> {
    this.completing ??= this.complete()
    return this.completing
  }

  private async complete(): Promise<string | undefined> {
    if (window.opener && window.name === popupName) {
      // a popup: hand the answer to the opener, which holds the state (this window has an older copy)
      const issuer = this.remembered() ?? this.issuers[0]
      await this.manager(issuer).signinPopupCallback()
      return undefined
    }
    const issuer = this.issuerOfState() ?? this.remembered()
    if (!issuer) throw new Error('no sign-in is in progress in this tab')
    const user = await this.manager(issuer).signinRedirectCallback()
    this.set(user)
    const state = user.state as { returnTo?: string } | undefined
    return localPath(state?.returnTo) ?? '/secrets'
  }

  /** the issuer the returning sign-in began with: its stored state names it */
  private issuerOfState(): IssuerConfig | undefined {
    const state = new URLSearchParams(window.location.search).get('state')
    if (!state) return undefined
    try {
      const stored = JSON.parse(sessionStorage.getItem(`oidc.${state}`) ?? '{}') as { authority?: string }
      return this.issuers.find((i) => i.issuer === stored.authority)
    } catch {
      return undefined
    }
  }

  /** signs in again in a popup: the page and an editor's input stay as they are */
  async renew(): Promise<void> {
    const issuer = this.remembered()
    if (!issuer) throw new Error('no issuer to sign in again with')
    this.set(await this.manager(issuer).signinPopup())
  }

  async token(): Promise<string> {
    if (!this.user || this.user.expired) {
      this.notify() // the banner shows now, not at the next render
      throw new SessionEnded()
    }
    return this.user.access_token
  }

  /** ends the session here and at the IdP (a shared machine signs in anew); the refresh token revoked first */
  async signOut(): Promise<void> {
    const issuer = this.remembered()
    sessionStorage.removeItem(lastIssuer)
    if (!issuer) {
      this.set(null)
      return
    }
    const m = this.manager(issuer)
    await m.revokeTokens(['refresh_token']).catch(() => undefined)
    try {
      await m.signoutRedirect({ id_token_hint: this.user?.id_token })
    } catch {
      this.set(null) // no end-session endpoint: this tab forgets the user
      await m.removeUser()
    }
  }
}

export class SessionEnded extends Error {
  constructor() {
    super('the session ended: sign in again')
  }
}

/** a path within the console to go back to after a sign-in, or undefined: one slash first, then neither a slash
 * nor a backslash - '//host' would leave the origin, and a browser reads a backslash as a slash - and no
 * backslash or control character anywhere. The router's own check is the second line. */
export function localPath(p: string | undefined): string | undefined {
  if (!p || !p.startsWith('/') || p.startsWith('//') || p.startsWith('/\\')) return undefined
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(p)) return undefined
  return p
}
