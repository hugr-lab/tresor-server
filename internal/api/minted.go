package api

// Secrets minted for the caller (specs/010): `provider: token_exchange`, an `audience` (and a `scope`); the
// material is a token for the caller at the identity provider - the caller's own when it reads directly, the
// grant's user's under a delegation grant (never the server's). Tokens are never logged nor put in an error.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hugr-lab/tresor-server/internal/auth"
	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/mint"
	"github.com/hugr-lab/tresor-server/internal/state"
)

const (
	tokenExchangeProvider = "token_exchange"
	mintMargin            = 30 * time.Second // a minted token is renewed this long before it expires
	mintNoExpiry          = 60 * time.Second // a minted token the IdP gave no expiry is reused this long
	grantMintDeadline     = 10 * time.Second // all of a grant's exchanges, together
	refreshTimeout        = 15 * time.Second
)

// tokenParam is where a minted token goes, per secret type; a type not listed cannot be minted.
var tokenParam = map[string]string{"http": "bearer_token", "quack": "token"}

var errNoExchange = errors.New("this service cannot mint tokens for the caller's issuer (no exchange client)")

func isMinted(sec *state.Secret) bool { return sec.Provider == tokenExchangeProvider }

// mintTarget is a minted secret's audience and scope, from its params.
func mintTarget(params map[string]json.RawMessage) (audience, scope string) {
	str := func(key string) string {
		var v string
		if raw, ok := params[key]; ok {
			_ = json.Unmarshal(raw, &v)
		}
		return v
	}
	return str("audience"), str("scope")
}

// validMinted checks a token_exchange secret at PUT: a known type, a text audience that is not this
// service's own, a text scope if any, and no token of its own.
func (s *Server) validMinted(typ string, params map[string]json.RawMessage) error {
	param, ok := tokenParam[strings.ToLower(typ)]
	if !ok {
		return fmt.Errorf("a %s secret has no token parameter to mint (http, quack)", tokenExchangeProvider)
	}
	audience, scope := mintTarget(params)
	if audience == "" {
		return fmt.Errorf("a %s secret names its audience (a string parameter)", tokenExchangeProvider)
	}
	if raw, has := params["scope"]; has && scope == "" && string(raw) != `""` {
		return fmt.Errorf("a %s secret's scope is a string", tokenExchangeProvider)
	}
	for _, is := range s.cfg.Issuers {
		if audience == is.Audience {
			// a user's token for this service, in a secret sent to another server, could be replayed here
			return fmt.Errorf("a %s secret's audience is another service's, never this one's", tokenExchangeProvider)
		}
	}
	for key := range params {
		if strings.EqualFold(key, param) {
			return fmt.Errorf("a %s secret stores no %s: the service mints it", tokenExchangeProvider, param)
		}
	}
	return nil
}

// mintKey identifies a minted token: the audience and the scope - all a token depends on.
func mintKey(audience, scope string) string { return audience + "\x00" + scope }

// mintResult is what minting at a grant's exchange gave for one audience: a token, or the IdP's lasting
// refusal (an outage leaves both empty: minted lazily later).
type mintResult struct {
	token  *mint.Token
	failed string
}

// mintLocks serialise one replica's renewals of one grant's token for one audience (other replicas are held
// off by the store's compare-and-set). A lock lives while someone holds or waits for it; waiting ends with
// the request.
type mintLocks struct {
	mu    sync.Mutex
	locks map[string]*mintLock
}

type mintLock struct {
	ch   chan struct{}
	refs int
}

func (m *mintLocks) lock(ctx context.Context, key string) (unlock func(), err error) {
	m.mu.Lock()
	if m.locks == nil {
		m.locks = map[string]*mintLock{}
	}
	l := m.locks[key]
	if l == nil {
		l = &mintLock{ch: make(chan struct{}, 1)}
		m.locks[key] = l
	}
	l.refs++
	m.mu.Unlock()
	release := func() {
		m.mu.Lock()
		if l.refs--; l.refs == 0 {
			delete(m.locks, key)
		}
		m.mu.Unlock()
	}
	select {
	case l.ch <- struct{}{}:
		return func() { <-l.ch; release() }, nil
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	}
}

// storeMinted stores a grant's minted token (or its refusal) at a version, sealed by the store.
func (s *Server) storeMinted(ctx context.Context, idHash []byte, key string, version int64, res mintResult) error {
	t := state.MintedToken{Key: key, Version: version, Failed: res.failed}
	if res.token != nil {
		raw, err := json.Marshal(res.token)
		if err != nil {
			return err
		}
		t.Token = raw
	}
	return s.store.Delegations().PutToken(ctx, idHash, t)
}

// loadMinted reads a grant's minted token: the token (nil when none, or refused), the refusal, the version.
func (s *Server) loadMinted(ctx context.Context, idHash []byte, key string) (*mint.Token, string, int64, error) {
	t, err := s.store.Delegations().Token(ctx, idHash, key)
	if errors.Is(err, state.ErrNotFound) {
		return nil, "", 0, nil
	}
	if err != nil {
		return nil, "", 0, err
	}
	var token *mint.Token
	if t.Token != nil {
		token = &mint.Token{}
		if err := json.Unmarshal(t.Token, token); err != nil {
			return nil, "", 0, fmt.Errorf("a minted token does not read (%v): %w", err, keys.ErrSealed)
		}
	}
	return token, t.Failed, t.Version, nil
}

// directCache caches the tokens minted for callers reading directly, until shortly before they expire.
type directCache struct {
	mu     sync.Mutex
	tokens map[string]*mint.Token // caller owner \x00 audience \x00 scope -> token
}

// mintProblem is a minted secret's refusal: status, type and a detail with no token in it.
type mintProblem struct {
	status       int
	kind, detail string
}

func refusedMint(detail string) *mintProblem {
	return &mintProblem{http.StatusForbidden, "mint_refused", detail}
}

func unavailableMint(detail string) *mintProblem {
	return &mintProblem{http.StatusServiceUnavailable, "service_unavailable", detail}
}

// storeMintProblem is a store failure under a grant: a token that does not open is 500 service_error (an
// operator acts), anything else 503 (try later).
func storeMintProblem(err error, detail string) *mintProblem {
	if errors.Is(err, keys.ErrSealed) {
		return &mintProblem{http.StatusInternalServerError, "service_error", "a value the service holds does not open"}
	}
	return unavailableMint(detail)
}

func (s *Server) mintClient(ctx context.Context, issuer string) (*mint.Client, *mintProblem) {
	var ex *config.ExchangeClient
	for i := range s.cfg.Issuers {
		if config.IssuerKey(s.cfg.Issuers[i].Issuer) == config.IssuerKey(issuer) {
			ex = s.cfg.Issuers[i].Exchange
		}
	}
	if ex == nil {
		return nil, &mintProblem{http.StatusUnprocessableEntity, "invalid_secret", errNoExchange.Error()}
	}
	tokenURL, err := s.verifier.TokenURL(ctx, issuer)
	if err != nil {
		return nil, unavailableMint("the identity provider's token endpoint is not known yet")
	}
	// the client secret goes there: https, or http only to this machine (as the issuers themselves)
	if u, err := url.Parse(tokenURL); err != nil ||
		!(u.Scheme == "https" || (u.Scheme == "http" && config.IsLoopback(u.Hostname()))) {
		return nil, unavailableMint("the identity provider's token endpoint is not https")
	}
	return &mint.Client{TokenURL: tokenURL, ClientID: ex.ClientID, ClientSecret: ex.ClientSecret, Now: s.now}, nil
}

// checkMinted refuses a token not meant for the audience asked, or meant for this service itself: an IdP
// that ignored the audience must not have a token for the service end up in a secret sent elsewhere.
func (s *Server) checkMinted(token *mint.Token, audience string) error {
	auds, isJWT := mint.Audiences(token.Access)
	if !isJWT {
		return nil // an opaque token: its audience is the IdP's word
	}
	if !slices.Contains(auds, audience) {
		return errors.New("the identity provider minted a token not meant for " + audience)
	}
	for _, is := range s.cfg.Issuers {
		if slices.Contains(auds, is.Audience) {
			return errors.New("the identity provider minted a token meant for this service")
		}
	}
	return nil
}

// mintAtGrant: at a grant's exchange, the user's token is exchanged - with a refresh token - for every
// audience the actor may mint, concurrently and under one deadline; the results are stored with the grant.
// The subject token is kept (sealed) until it expires, for what could not be minted now.
func (s *Server) mintAtGrant(ctx context.Context, user *auth.Caller, subject string, actor *auth.Caller) map[string]mintResult {
	secrets, err := s.store.List(ctx)
	if err != nil {
		s.log.Error("store read failed", "error", err.Error())
		return nil // minted lazily from the subject token, while it lives
	}
	targets := map[string][2]string{}
	for _, listed := range secrets {
		if isMinted(listed) && usable(listed, actor.Principals) {
			sec, err := s.store.Get(ctx, listed.Name) // a list carries no params: the audience is in them
			if err != nil {
				s.log.Error("store read failed", "secret", listed.Name, "error", err.Error())
				continue // minted lazily, or refused at the read with the reason
			}
			audience, scope := mintTarget(sec.Params)
			targets[mintKey(audience, scope)] = [2]string{audience, scope}
		}
	}
	if len(targets) == 0 {
		return nil
	}
	client, problem := s.mintClient(ctx, user.Issuer)
	if problem != nil {
		return nil // minted lazily from the subject token, or refused at the read with the reason
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), grantMintDeadline)
	defer cancel()
	results := map[string]mintResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for key, target := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := client.Exchange(ctx, subject, target[0], target[1], true)
			if err == nil {
				err = s.checkMinted(token, target[0])
			}
			s.auditMint(ctx, target[0], "minted", err)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				results[key] = mintResult{token: token}
			case isRefusal(err):
				results[key] = mintResult{failed: err.Error()} // the IdP's word, redacted; outages retried lazily
				fallthrough
			default:
				s.log.Warn("minting at a grant failed", "actor", actor.Client(), "user", user.Owner(),
					"audience", target[0], "reason", err.Error())
			}
		}()
	}
	wg.Wait()
	return results
}

// isRefusal: the IdP answered no (a lasting refusal), as opposed to not answering (an outage).
func isRefusal(err error) bool {
	var e *mint.Error
	return errors.As(err, &e) && !e.Transient()
}

// mintedToken is the token a minted secret's material carries for this request's caller, or the problem.
func (s *Server) mintedToken(r *http.Request, c *auth.Caller, sec *state.Secret) (*mint.Token, *mintProblem) {
	audience, scope := mintTarget(sec.Params)
	key := mintKey(audience, scope)
	now := s.now()
	fresh := func(t *mint.Token) bool { return t != nil && t.Expiry.Sub(now) > mintMargin }
	if gr := grantOf(r); gr != nil {
		return s.mintedForGrant(r, gr, key, audience, scope, fresh)
	}
	// directly: the caller's own token, exchanged on demand; cached per caller and audience until shortly
	// before it expires
	cacheKey := c.Owner() + "\x00" + key
	s.direct.mu.Lock()
	if token := s.direct.tokens[cacheKey]; fresh(token) {
		s.direct.mu.Unlock()
		return token, nil
	}
	s.direct.mu.Unlock()
	client, problem := s.mintClient(r.Context(), c.Issuer)
	if problem != nil {
		return nil, problem
	}
	token, err := client.Exchange(r.Context(), bearerOf(r), audience, scope, false)
	if err == nil {
		err = s.checkMinted(token, audience)
	}
	s.auditMint(r.Context(), audience, "minted", err)
	if err != nil {
		s.log.Warn("minting for the caller failed", "caller", c.Owner(), "audience", audience, "reason", err.Error())
		if isRefusal(err) || strings.Contains(err.Error(), "minted a token") {
			return nil, refusedMint("the identity provider refused to mint a token for the caller: " + err.Error())
		}
		return nil, unavailableMint("the identity provider did not answer")
	}
	if token.Expiry.IsZero() {
		token.Expiry = now.Add(mintNoExpiry)
	}
	s.direct.mu.Lock()
	if s.direct.tokens == nil {
		s.direct.tokens = map[string]*mint.Token{}
	}
	for k, t := range s.direct.tokens { // expired entries go: a bounded cache
		if !t.Expiry.After(now) {
			delete(s.direct.tokens, k)
		}
	}
	s.direct.tokens[cacheKey] = token
	s.direct.mu.Unlock()
	return token, nil
}

// mintedForGrant: under a grant, the grant's user's token - minted at the exchange (or lazily from the
// subject token while it lives), renewed from its refresh token. Every replica reads it from the store; a
// renewal is compare-and-set, and a replica that loses the race takes the winner's token rather than spend a
// rotated refresh token twice.
func (s *Server) mintedForGrant(r *http.Request, gr *grant, key, audience, scope string,
	fresh func(*mint.Token) bool) (*mint.Token, *mintProblem) {
	usable := func(t *mint.Token) bool { return fresh(t) || (t != nil && t.Expiry.IsZero()) }
	// a fresh token needs no lock
	if token, _, _, err := s.loadMinted(r.Context(), gr.idHash, key); err == nil && usable(token) {
		return token, nil
	}
	unlock, err := s.mintLocks.lock(r.Context(), hex.EncodeToString(gr.idHash)+"\x00"+key)
	if err != nil {
		return nil, unavailableMint("the request ended while the grant's token was being renewed")
	}
	defer unlock()
	// detached from the request: a refresh token the IdP rotated must not be lost with a dropped connection
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), refreshTimeout)
	defer cancel()
	for range 3 {
		token, failed, version, err := s.loadMinted(ctx, gr.idHash, key)
		if err != nil {
			s.log.Error("a grant's minted token: the store failed", "error", err.Error())
			return nil, storeMintProblem(err, "the grant's token could not be read")
		}
		if usable(token) {
			return token, nil
		}
		client, problem := s.mintClient(ctx, gr.user.Issuer)
		if problem != nil {
			return nil, problem
		}
		var next mintResult
		switch {
		case token != nil && token.Refresh != "":
			renewed, err := client.Refresh(ctx, token.Refresh)
			if err == nil {
				err = s.checkMinted(renewed, audience)
			}
			s.auditMint(ctx, audience, "refreshed", err)
			if err != nil {
				if _, _, now, rerr := s.loadMinted(ctx, gr.idHash, key); rerr == nil && now != version {
					continue // another replica renewed it meanwhile (and spent the refresh token): take its
				}
				if mint.IsInvalidGrant(err) {
					next = mintResult{failed: sessionEnded}
					break
				}
				s.log.Warn("renewing a minted token failed", "user", gr.user.Owner(), "audience", audience,
					"reason", err.Error())
				if !isRefusal(err) {
					return nil, unavailableMint("the identity provider did not renew the token")
				}
				next = mintResult{failed: "renewing the user's token was refused: " + err.Error()}
				break
			}
			next = mintResult{token: renewed}
		case failed != "":
			return nil, refusedMint(refusal(failed))
		case !gr.keepsSubject:
			return nil, refusedMint("this grant carries no minted tokens: a new session mints them")
		default:
			// nothing minted yet (an outage at the exchange, or a secret granted to the server since): from
			// the subject token, while it lives
			subject, err := s.store.Delegations().SubjectToken(ctx, gr.idHash, s.now())
			if errors.Is(err, state.ErrNotFound) {
				return nil, refusedMint("the grant's user token has expired: a new session mints it")
			}
			if err != nil {
				s.log.Error("a grant's subject token: the store failed", "error", err.Error())
				return nil, storeMintProblem(err, "the grant's token could not be read")
			}
			minted, err := client.Exchange(ctx, string(subject), audience, scope, true)
			clear(subject)
			if err == nil {
				err = s.checkMinted(minted, audience)
			}
			s.auditMint(ctx, audience, "minted", err)
			if err != nil {
				s.log.Warn("minting for the grant's user failed", "user", gr.user.Owner(), "audience", audience,
					"reason", err.Error())
				if !isRefusal(err) && !strings.Contains(err.Error(), "minted a token") {
					return nil, unavailableMint("the identity provider did not answer")
				}
				next = mintResult{failed: "minting for the user was refused: " + err.Error()}
				break
			}
			next = mintResult{token: minted}
		}
		err = s.storeMintedRetried(ctx, gr.idHash, key, version+1, next)
		if errors.Is(err, state.ErrConflict) && next.token != nil {
			// another replica wrote first. When it wrote a failure - it may have tried the refresh token this
			// replica had just spent - the good token this one holds goes over it
			if now, failedNow, v, rerr := s.loadMinted(ctx, gr.idHash, key); rerr == nil && now == nil && failedNow != "" {
				err = s.storeMintedRetried(ctx, gr.idHash, key, v+1, next)
			}
		}
		switch {
		case errors.Is(err, state.ErrConflict):
			continue // another replica stored a token first: read it
		case errors.Is(err, state.ErrNotFound):
			return nil, refusedMint("the delegation grant has been revoked")
		case err != nil:
			// a renewed refresh token that could not be stored is lost: an outage, said as one
			s.log.Error("a grant's minted token could not be stored", "error", err.Error())
			return nil, unavailableMint("the grant's renewed token could not be stored")
		}
		if next.token == nil {
			return nil, refusedMint(refusal(next.failed))
		}
		return next.token, nil
	}
	return nil, unavailableMint("the grant's token kept changing")
}

const sessionEnded = "the user's session at the identity provider has ended"

// refusal is a kept failure as the caller reads it.
func refusal(failed string) string {
	if failed == sessionEnded || strings.HasPrefix(failed, "renewing the user's token was refused") ||
		strings.HasPrefix(failed, "minting for the user was refused") {
		return failed
	}
	return "minting for the user was refused: " + failed // a refusal kept at the exchange
}

// storeMintedRetried stores a token, again after a failure that is neither a conflict nor a revoked grant: a
// renewed refresh token is lost if it is not stored.
func (s *Server) storeMintedRetried(ctx context.Context, idHash []byte, key string, version int64, res mintResult) error {
	var err error
	for attempt := range 3 {
		err = s.storeMinted(ctx, idHash, key, version, res)
		if err == nil || errors.Is(err, state.ErrConflict) || errors.Is(err, state.ErrNotFound) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(time.Duration(100*(attempt+1)) * time.Millisecond):
		}
	}
	return err
}

// bearerOf is the raw bearer token of the request (verified already by authed).
func bearerOf(r *http.Request) string {
	_, raw, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	return strings.TrimSpace(raw)
}
