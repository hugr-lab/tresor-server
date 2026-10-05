// Sign-in (spec 010): OIDC Authorization Code + PKCE against an issuer's public client. The access token stays in
// memory - never in localStorage - and only the PKCE state rides in sessionStorage across the redirect. A reload
// signs in again through the IdP's own session, without a prompt when it has one. Renewal is by a refresh token,
// never in a hidden frame (the page's CSP has no frame-src).
import { InMemoryWebStorage, UserManager, WebStorageStateStore, type User } from 'oidc-client-ts'
import type { IssuerConfig } from './config'

const lastIssuer = 'tresor.issuer' // which issuer this tab signed in with: a URL, no secret

export class Session {
  private managers = new Map<string, UserManager>()
  private user: User | null = null
  private listeners = new Set<() => void>()

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
    await this.manager(issuer).signinRedirect({ state: { returnTo } })
  }

  /** completes a sign-in: a redirect's (the path to go back to), or a popup's (undefined: the window closes) */
  async callback(): Promise<string | undefined> {
    const issuer = this.remembered() ?? (window.opener ? this.issuers[0] : undefined)
    if (!issuer) throw new Error('no sign-in is in progress in this tab')
    const user = await this.manager(issuer).signinCallback()
    if (!user) return undefined // a popup: its opener has the user now
    this.set(user)
    const state = user.state as { returnTo?: string } | undefined
    return state?.returnTo && state.returnTo.startsWith('/') ? state.returnTo : '/secrets'
  }

  /** signs in again in a popup: the page and an editor's input stay as they are */
  async renew(): Promise<void> {
    const issuer = this.remembered()
    if (!issuer) throw new Error('no issuer to sign in again with')
    this.set(await this.manager(issuer).signinPopup())
  }

  async token(): Promise<string> {
    if (!this.user || this.user.expired) throw new SessionEnded()
    return this.user.access_token
  }

  async signOut(): Promise<void> {
    const issuer = this.remembered()
    sessionStorage.removeItem(lastIssuer)
    this.set(null)
    if (issuer) await this.manager(issuer).removeUser()
  }
}

export class SessionEnded extends Error {
  constructor() {
    super('the session ended: sign in again')
  }
}
