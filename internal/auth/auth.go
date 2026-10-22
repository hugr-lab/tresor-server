// Package auth verifies bearer tokens against the configured issuers and turns their claims into
// principals (specs/003). It never logs or returns a token.
//
// Taken over from tresor's reference server at 6133d0d (MIT, the same owner; see NOTICE). specs/NNN here are
// tresor's specs; spec NNN (with a space) are this repository's.
package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/hugr-lab/tresor-server/internal/config"
)

// Caller is who a verified token speaks for.
type Caller struct {
	Issuer     string
	Subject    string
	Principals []string // subject:, role:, group:, client:
	Service    bool     // a client-credentials token (the issuer's service rule): Principals carries client:
	ExpiresAt  time.Time
	// Actor is set when a server acts for this user through a delegation grant (specs/007): its client:
	// principal. The rest of the Caller is the user's, as taken at the grant's exchange.
	Actor       string
	ActorIssuer string // the issuer of the actor's token
	// ActorPrincipals are the actor's own (specs/009): under a grant the service applies the actor's
	// permissions, never the user's - the user gets nothing beyond what the server was granted.
	ActorPrincipals []string
	// Claims are the token's top-level text claims (a string, a number or a boolean as its JSON text) that a
	// generated parameter may serve (spec 023, mint+claim://) - never the session's or a token's binding
	// (sid, jti, nonce, …), never a list or an object. Kept with a delegation grant: the grant's user's.
	Claims map[string]string `json:",omitempty"`
	// Name is who the subject is, for people to read (spec 030, tresor spec 041: whoami's name): the first
	// non-blank of preferred_username, name, email, upn. Never an identity: nothing is granted, owned or audited
	// by it. Kept with a delegation grant: the grant's user's.
	Name string `json:",omitempty"`
}

// Client is the caller's client: principal (a service), or "".
func (c *Caller) Client() string {
	for _, p := range c.Principals {
		if strings.HasPrefix(p, "client:") {
			return p
		}
	}
	return ""
}

// Owner is the principal a caller's creations belong to: always its subject: - iss and sub, unique
// across issuers and across callers. (A client: principal is a client's name, shared by every token
// of that client and, with several issuers, by same-named clients of each: it names who may do
// something, never who someone is.)
func (c *Caller) Owner() string {
	return "subject:" + c.Issuer + "|" + c.Subject
}

// Has says whether the caller holds principal p.
func (c *Caller) Has(p string) bool { return slices.Contains(c.Principals, p) }

// ErrUnauthenticated is every verification failure, as the client sees it; the wrapped reason is for
// the server's log only.
var ErrUnauthenticated = errors.New("unauthenticated")

// Verifier checks tokens of every configured issuer. Issuers are discovered lazily and retried, so the
// server may start before its identity provider does.
type Verifier struct {
	issuers map[string]*issuer
	order   []string
	// Now is the clock (tests move it).
	Now func() time.Time
}

type issuer struct {
	cfg        config.Issuer
	client     *http.Client // its discovery's and keys': ca_file trusted, discovery_token_file sent (spec 026)
	mu         sync.Mutex
	verifier   *oidc.IDTokenVerifier
	tokenURL   string    // the issuer's token endpoint, from the same discovery (specs/010: exchanges)
	jwksURL    string    // its signing keys, fetched for readiness (CheckIssuer)
	answered   bool      // its keys were fetched once
	failedAt   time.Time // the last failed discovery: retried after retryAfter, not on every request
	lastFailed error
}

// discoveryTimeout bounds one discovery (the lock is held across it); retryAfter spaces the retries
// after a failure, so tokens naming an unreachable issuer do not each trigger an outbound request.
const (
	discoveryTimeout = 10 * time.Second
	retryAfter       = 5 * time.Second
)

// NewVerifier prepares (without contacting them) the issuers of cfg.
func NewVerifier(cfg []config.Issuer) *Verifier {
	v := &Verifier{issuers: map[string]*issuer{}, Now: time.Now}
	for _, is := range cfg {
		v.issuers[config.IssuerKey(is.Issuer)] = &issuer{cfg: is}
		v.order = append(v.order, is.Issuer)
	}
	return v
}

func (is *issuer) get(ctx context.Context, now func() time.Time) (*oidc.IDTokenVerifier, error) {
	is.mu.Lock()
	defer is.mu.Unlock()
	if is.verifier != nil {
		return is.verifier, nil
	}
	if is.lastFailed != nil && now().Sub(is.failedAt) < retryAfter {
		return nil, is.lastFailed
	}
	// bounded, and not the request's context: one caller's deadline must not fail the discovery for
	// everyone, and a hung IdP must not hold the lock for long
	discoverCtx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
	defer cancel()
	client, err := is.httpClient()
	if err != nil {
		is.failedAt, is.lastFailed = now(), fmt.Errorf("issuer %s: %w", is.cfg.Issuer, err)
		return nil, is.lastFailed
	}
	discoverCtx = oidc.ClientContext(discoverCtx, client)
	provider, err := oidc.NewProvider(discoverCtx, is.cfg.Issuer) // discovery + the RFC 8414 issuer check
	if err != nil {
		is.failedAt, is.lastFailed = now(), fmt.Errorf("issuer %s not reachable yet: %w", is.cfg.Issuer, err)
		return nil, is.lastFailed
	}
	is.tokenURL = provider.Endpoint().TokenURL
	var meta struct {
		JWKS string `json:"jwks_uri"`
	}
	if err := provider.Claims(&meta); err == nil {
		is.jwksURL = meta.JWKS
		if t, ok := client.Transport.(*tokenTransport); ok { // its keys are read with the token too
			if u, err := url.Parse(meta.JWKS); err == nil && u.Scheme == "https" {
				t.allow(u.Host)
			}
		}
	}
	// the JWKS is fetched later, by Verify, under the same bounded client (go-oidc keeps the client
	// of this context, not its deadline)
	is.verifier = provider.Verifier(&oidc.Config{
		// the audience is checked below against the configured one: go-oidc's ClientID check is the
		// same test, but an access token's aud is not a client id, so it is done explicitly
		SkipClientIDCheck:    true,
		SupportedSigningAlgs: is.cfg.Algorithms,
		Now:                  now,
	})
	return is.verifier, nil
}

// httpClient is the issuer's client for its discovery and keys, made once: the system's roots plus ca_file,
// and discovery_token_file's token sent to the issuer's host (and, once discovered, its keys' host) only.
// Called under is.mu.
func (is *issuer) httpClient() (*http.Client, error) {
	if is.client != nil {
		return is.client, nil
	}
	if is.cfg.CAFile == "" && is.cfg.DiscoveryTokenFile == "" {
		is.client = &http.Client{Timeout: discoveryTimeout}
		return is.client, nil
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if is.cfg.CAFile != "" {
		pem, err := os.ReadFile(is.cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		// with a token to send, the cluster's CA only: the token reaches no host a public CA certifies (a cloud's
		// public issuer, a CDN serving the keys); without one, the system's roots too
		var pool *x509.CertPool
		if is.cfg.DiscoveryTokenFile == "" {
			pool, _ = x509.SystemCertPool()
		}
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file holds no PEM certificate")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	var rt http.RoundTripper = transport
	if is.cfg.DiscoveryTokenFile != "" {
		u, err := url.Parse(is.cfg.Issuer)
		if err != nil {
			return nil, err
		}
		rt = &tokenTransport{next: transport, file: is.cfg.DiscoveryTokenFile, hosts: map[string]bool{u.Host: true}}
	}
	is.client = &http.Client{Timeout: discoveryTimeout, Transport: rt}
	return is.client, nil
}

// tokenTransport sends a token read from a file, at each request, to the hosts it allows - https only, never
// on a redirect elsewhere. The token is never logged.
type tokenTransport struct {
	next  http.RoundTripper
	file  string
	mu    sync.Mutex
	hosts map[string]bool
}

func (t *tokenTransport) allow(host string) {
	t.mu.Lock()
	t.hosts[host] = true
	t.mu.Unlock()
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	allowed := t.hosts[req.URL.Host]
	t.mu.Unlock()
	if !allowed || req.URL.Scheme != "https" {
		return t.next.RoundTrip(req)
	}
	raw, err := os.ReadFile(t.file)
	if err != nil {
		return nil, fmt.Errorf("discovery_token_file: %w", err) // the path's error, never the token
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return nil, errors.New("discovery_token_file is empty")
	}
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+token)
	return t.next.RoundTrip(r)
}

// Issuers are the configured issuers' identifiers, in the configuration's order.
func (v *Verifier) Issuers() []string { return v.order }

// CheckIssuer says whether an issuer answers now: its discovery, and its signing keys (spec 002, /readyz).
// The error names the issuer; it is for the log. Its keys are fetched on every check: a readiness probe
// runs it in the background, every 30 s.
func (v *Verifier) CheckIssuer(ctx context.Context, iss string) error {
	is, ok := v.issuers[config.IssuerKey(iss)]
	if !ok {
		return fmt.Errorf("issuer %q is not configured", iss)
	}
	if _, err := is.get(ctx, v.Now); err != nil {
		return err
	}
	is.mu.Lock()
	url := is.jwksURL
	is.mu.Unlock()
	if url == "" {
		return fmt.Errorf("issuer %s names no jwks_uri", is.cfg.Issuer)
	}
	fetchCtx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("issuer %s: jwks_uri: %w", is.cfg.Issuer, err)
	}
	is.mu.Lock()
	client := is.client
	is.mu.Unlock()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("issuer %s: its signing keys are not reachable: %w", is.cfg.Issuer, err)
	}
	defer resp.Body.Close()
	var keys struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&keys) != nil ||
		len(keys.Keys) == 0 {
		return fmt.Errorf("issuer %s: its signing keys did not answer (%d)", is.cfg.Issuer, resp.StatusCode)
	}
	is.mu.Lock()
	is.answered = true
	is.mu.Unlock()
	return nil
}

// Answered says whether an issuer's keys have been fetched once: after that, its outage leaves the service
// ready (the keys it verifies with are cached) - reported, not fatal.
func (v *Verifier) Answered(iss string) bool {
	is, ok := v.issuers[config.IssuerKey(iss)]
	if !ok {
		return false
	}
	is.mu.Lock()
	defer is.mu.Unlock()
	return is.answered
}

// TokenURL is the token endpoint of a configured issuer (by a token's iss), from its discovery.
func (v *Verifier) TokenURL(ctx context.Context, iss string) (string, error) {
	is, ok := v.issuers[config.IssuerKey(iss)]
	if !ok {
		return "", fmt.Errorf("issuer %q is not configured", iss)
	}
	if _, err := is.get(ctx, v.Now); err != nil {
		return "", err
	}
	is.mu.Lock()
	defer is.mu.Unlock()
	if is.tokenURL == "" {
		return "", fmt.Errorf("issuer %q names no token endpoint", iss)
	}
	return is.tokenURL, nil
}

// Verify checks a raw bearer token and returns its caller. Every failure wraps ErrUnauthenticated.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Caller, error) {
	iss, err := unverifiedIssuer(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	is, ok := v.issuers[config.IssuerKey(iss)]
	if !ok {
		return nil, fmt.Errorf("%w: issuer %q is not configured", ErrUnauthenticated, iss)
	}
	verifier, err := is.get(ctx, v.Now)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	token, err := verifier.Verify(ctx, raw) // signature, iss, exp, the configured algorithms
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	if !slices.Contains(token.Audience, is.cfg.Audience) {
		return nil, fmt.Errorf("%w: aud %v does not contain %q", ErrUnauthenticated, token.Audience, is.cfg.Audience)
	}
	var payload json.RawMessage
	if err := token.Claims(&payload); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrUnauthenticated, err)
	}
	var claims map[string]any
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber() // a number claim served as its JSON text, every digit kept
	if err := dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrUnauthenticated, err)
	}
	if token.Subject == "" {
		return nil, fmt.Errorf("%w: no sub", ErrUnauthenticated)
	}
	return callerFrom(is.cfg, token.Issuer, token.Subject, token.Expiry, claims), nil
}

// displayName is who the subject is, for people to read: the first non-blank of preferred_username, name, email,
// upn (Entra v1) - trimmed, no control character, 256 characters at most.
func displayName(claims map[string]any) string {
	for _, k := range []string{"preferred_username", "name", "email", "upn"} {
		s, _ := claims[k].(string)
		s = strings.TrimSpace(s)
		if s == "" || strings.IndexFunc(s, unicode.IsControl) >= 0 {
			continue
		}
		if r := []rune(s); len(r) > 256 {
			s = string(r[:256])
		}
		return s
	}
	return ""
}

// ignored: a role an issuer's ignore_roles names (glob patterns, path.Match's).
func ignored(patterns []string, role string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, role); ok {
			return true
		}
	}
	return false
}

// maxClaim bounds a kept claim's text: a claim is a name or an id, not a document.
const maxClaim = 4096

// BindingClaims name the user's session at the IdP or bind one token (Entra's uti, rh, aio too): never kept,
// never served (tresor spec 029).
var BindingClaims = map[string]bool{"sid": true, "session_state": true, "jti": true, "nonce": true,
	"at_hash": true, "c_hash": true, "s_hash": true, "uti": true, "rh": true, "aio": true}

// textClaims are the claims a generated parameter may serve: top-level, a string, a number or a boolean.
func textClaims(claims map[string]any) map[string]string {
	out := map[string]string{}
	for name, v := range claims {
		if BindingClaims[name] {
			continue
		}
		var text string
		switch t := v.(type) {
		case string:
			text = t
		case json.Number:
			text = t.String()
		case bool:
			text = strconv.FormatBool(t)
		default:
			continue
		}
		// no control character (CR, LF, NUL, …): a claim a user may edit is put inside strings a consumer
		// parses - a header, a connection string
		if text != "" && len(text) <= maxClaim && strings.IndexFunc(text, unicode.IsControl) < 0 {
			out[name] = text
		}
	}
	return out
}

// callerFrom maps claims to principals: identity is iss+sub, never an email or a username. A service
// is recognised only by the issuer's configured rule: no claim marks one by convention.
func callerFrom(cfg config.Issuer, iss, sub string, exp time.Time, claims map[string]any) *Caller {
	c := &Caller{Issuer: iss, Subject: sub, ExpiresAt: exp, Claims: textClaims(claims), Name: displayName(claims)}
	c.Principals = append(c.Principals, "subject:"+iss+"|"+sub)
	for _, r := range stringsAt(claims, cfg.RolesClaim) {
		if ignored(cfg.IgnoreRoles, r) {
			continue // an IdP's own roles (Keycloak's offline_access, default-roles-*): never a principal here
		}
		c.Principals = append(c.Principals, "role:"+r)
	}
	for _, g := range stringsAt(claims, cfg.GroupsClaim) {
		c.Principals = append(c.Principals, "group:"+strings.TrimPrefix(g, "/")) // Keycloak's groups are paths
	}
	if rule := cfg.Service; rule != nil {
		marker, present := claims[rule.Claim]
		matches := present && (rule.Equals == "" || marker == rule.Equals)
		if client := firstString(claims, rule.ClientClaim); matches && client != "" {
			c.Service = true
			c.Principals = append(c.Principals, "client:"+client)
		}
	}
	return c
}

func firstString(claims map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := claims[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// stringsAt reads a dotted path (realm_access.roles, resource_access.duckdb.roles, groups) as a list
// of strings; anything of another shape is nothing.
func stringsAt(claims map[string]any, dotted string) []string {
	if dotted == "" {
		return nil
	}
	var node any = claims
	for _, part := range strings.Split(dotted, ".") {
		m, ok := node.(map[string]any)
		if !ok {
			return nil
		}
		node = m[part]
	}
	var out []string
	switch v := node.(type) {
	case []any: // a list of names (Keycloak, Entra)
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	case map[string]any: // an object keyed by name (ZITADEL: {"role": {"<org id>": "<domain>"}}), spec 006
		for k := range v {
			if k != "" {
				out = append(out, k)
			}
		}
		slices.Sort(out)
	}
	return out
}

// unverifiedIssuer reads iss from a JWT's payload only to choose the verifier; nothing else of an
// unverified token is used.
func unverifiedIssuer(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("malformed payload")
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Iss == "" {
		return "", errors.New("no iss")
	}
	return claims.Iss, nil
}
