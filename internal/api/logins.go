package api

// Service logins (spec 023): a secret of type tresor_service_login says how the service logs in to another
// service - a user and a password, an OAuth2 client, a custom login and refresh - and is never served. A
// secret's `mint+login://<login>#<field>` serves one field of what the login got (an access token, a session
// id), made for the effective user; `mint+login:scope#<field>` picks the login by the secret's scope, the one
// bound to the effective user (its `subject`). What renews a login (a refresh token, a password) never leaves
// the service, and nothing a login reads or sends is logged.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hugr-lab/tresor-server/internal/auth"
	"github.com/hugr-lab/tresor-server/internal/login"
	"github.com/hugr-lab/tresor-server/internal/state"
)

// refreshHorizon: how long after its expiry a login's refresh token is kept to renew it.
const refreshHorizon = 12 * time.Hour

// isLogin: a service login, never served to a lookup.
func isLogin(sec *state.Secret) bool { return strings.EqualFold(sec.Type, login.Type) }

// loginCache keeps what logins got, per login (its version) and, for a login bound to a user or made of their
// claims, per user - in this replica's memory only.
type loginCache struct {
	mu      sync.Mutex
	entries map[string]*loginEntry
}

type loginEntry struct {
	result *login.Result
	kept   map[string]string // what renews it: never served
}

func (s *Server) loginClient() *login.Client {
	return &login.Client{Hosts: s.cfg.Dynamic.LoginHosts, Now: s.now, Identities: s.identities}
}

// textParams are a login's params as text: a string, or a typed VARCHAR's value.
func textParams(params map[string]json.RawMessage) (map[string]string, error) {
	out := make(map[string]string, len(params))
	for k, raw := range params {
		var str string
		if json.Unmarshal(raw, &str) == nil {
			out[k] = str
			continue
		}
		var typed struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		}
		if json.Unmarshal(raw, &typed) != nil || !strings.EqualFold(typed.Type, "VARCHAR") {
			return nil, errors.New("a login's parameter " + strconv.Quote(k) + " is not text")
		}
		out[k] = typed.Value
	}
	return out, nil
}

// checkLogin checks a login at a write: its params as a login (references and claims stood in for), its URLs
// within its scope and the allowed hosts.
func (s *Server) checkLogin(scope []string, params map[string]json.RawMessage) error {
	text, err := textParams(params)
	if err != nil {
		return err
	}
	refs := s.material.Refs(params)
	claims := claimKeys(params, refs)
	for k := range refs {
		text, _ := stringOf(params[k])
		for _, m := range claimPattern.FindAllString(text, -1) {
			if name := m[len("${claim://") : len(m)-1]; name == "" || auth.BindingClaims[name] {
				return errors.New("a login's parameter " + strconv.Quote(k) + " names no claim, or a session claim")
			}
		}
	}
	for k := range text {
		if refs[k] || claims[k] {
			if !isInput(k) {
				return errors.New("a login's parameter " + strconv.Quote(k) + " takes no reference or claim")
			}
			text[k] = "x" // stands in: resolved at the read
		}
	}
	spec, err := login.Parse(text, scope)
	if err != nil {
		return err
	}
	client := s.loginClient()
	for _, u := range spec.URLs() {
		if _, err := client.CheckURL(spec, u); err != nil {
			return err
		}
	}
	if refs["refresh_token"] || claims["refresh_token"] {
		// rotated tokens are written back: it is the login's own, sealed - never a reference's nor a user's claim
		return errors.New("a login's refresh_token is written as it is: not a reference, not a claim")
	}
	return client.CheckIdentity(spec) // a rule's or a jwt_assertion's identity: the operator's, bounded
}

// claimRef is a claim's text as it may go into a reference: a name or an id - never a path's separator or a
// climb, so a user's claim cannot point a reference elsewhere.
var claimRef = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,256}$`)

// claimsStoodIn: a login's references with their claims stood in for (a write checks the reference's shape
// and allowlist; the read checks them again with the user's claim in).
func claimsStoodIn(typ string, params map[string]json.RawMessage) map[string]json.RawMessage {
	if !strings.EqualFold(typ, login.Type) {
		return params
	}
	out := make(map[string]json.RawMessage, len(params))
	for k, raw := range params {
		out[k] = raw
		if text, ok := stringOf(raw); ok && strings.HasPrefix(text, "ref+") && strings.Contains(text, "${claim://") {
			out[k], _ = json.Marshal(claimPattern.ReplaceAllString(text, "x"))
		}
	}
	return out
}

var claimPattern = regexp.MustCompile(`\$\{claim://[^}]*\}`)

// stringOf is a param's text: a string, or a typed VARCHAR's value.
func stringOf(raw json.RawMessage) (string, bool) {
	var str string
	if json.Unmarshal(raw, &str) == nil {
		return str, true
	}
	var typed struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if json.Unmarshal(raw, &typed) == nil && strings.EqualFold(typed.Type, "VARCHAR") {
		return typed.Value, true
	}
	return "", false
}

// claimsIntoRefs puts the effective user's claims into a login's references, each checked as a name or an id.
func claimsIntoRefs(c *auth.Caller, params map[string]json.RawMessage, refs map[string]bool) (map[string]json.RawMessage, *mintProblem) {
	out := make(map[string]json.RawMessage, len(params))
	for k, raw := range params {
		out[k] = raw
		text, ok := stringOf(raw)
		if !refs[k] || !ok || !strings.Contains(text, "${claim://") {
			continue
		}
		var problem *mintProblem
		filled := claimPattern.ReplaceAllStringFunc(text, func(m string) string {
			name := m[len("${claim://") : len(m)-1]
			value := c.Claims[name]
			if auth.BindingClaims[name] || !claimRef.MatchString(value) || strings.Contains(value, "..") {
				problem = refusedMint("the caller's claim " + strconv.Quote(name) + " cannot name a reference (a name or an id only)")
			}
			return value
		})
		if problem != nil {
			return nil, problem
		}
		out[k], _ = json.Marshal(filled)
	}
	return out, nil
}

// claimKeys are a login's params that hold a claim - whole (mint+claim://) or a part (${claim://…}).
func claimKeys(params map[string]json.RawMessage, refs map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range refs { // a reference with a claim in it (ref+vault://kv/users/${claim://sub}#password)
		if text, ok := stringOf(params[k]); ok && strings.Contains(text, "${claim://") {
			out[k] = true
		}
	}
	gens, _ := generatorsOf(login.Type, "config", params, refs)
	for k, list := range gens {
		for _, gen := range list {
			if gen.kind == "claim" {
				out[k] = true
			}
		}
	}
	return out
}

// loginRedacted: a login's inputs are always redacted - the console's shape never shows them.
func loginRedacted(params map[string]json.RawMessage, redact []string) []string {
	var keys []string
	for _, in := range login.Inputs() {
		if _, ok := params[in]; ok {
			keys = append(keys, in)
		}
	}
	return withKeys(redact, keys)
}

func isInput(k string) bool {
	for _, in := range login.Inputs() {
		if k == in {
			return true
		}
	}
	return false
}

// loginField is one field of a login's result, for the effective user, with its expiry.
func (s *Server) loginField(r *http.Request, c *auth.Caller, consumer *state.Secret, gen *generator) (string, time.Time, *mintProblem) {
	sec, spec, problem := s.findLogin(r, c, consumer, gen)
	if problem != nil {
		return "", time.Time{}, problem
	}
	res, problem := s.loginResult(r, c, sec, spec)
	if problem != nil {
		return "", time.Time{}, problem
	}
	value, ok := res.Fields[gen.field]
	if !ok || value == "" {
		return "", time.Time{}, refusedMint("the service login " + strconv.Quote(sec.Name) + " gave no field " + strconv.Quote(gen.field))
	}
	return value, res.Expiry, nil
}

// findLogin: the login a generator names, or the one for the effective user by the consumer's scope - usable
// under the caller's grants (a role's or a group's, under a delegation grant the server's), bound to no user or
// to the effective user, its scope covering the consumer's.
func (s *Server) findLogin(r *http.Request, c *auth.Caller, consumer *state.Secret, gen *generator) (*state.Secret, *login.Spec, *mintProblem) {
	ctx := r.Context()
	var candidates []*state.Secret
	if gen.login != "" {
		sec, err := s.store.Get(ctx, gen.login)
		if errors.Is(err, state.ErrNotFound) || (err == nil && !isLogin(sec)) {
			return nil, nil, refusedMint("no service login " + strconv.Quote(gen.login))
		}
		if err != nil {
			s.log.Error("store read failed", "login", gen.login, "error", err.Error())
			return nil, nil, unavailableMint("the service login could not be read")
		}
		candidates = []*state.Secret{sec}
	} else {
		listed, err := s.store.List(ctx)
		if err != nil {
			s.log.Error("store read failed", "error", err.Error())
			return nil, nil, unavailableMint("the service logins could not be read")
		}
		for _, l := range listed {
			if !isLogin(l) {
				continue
			}
			sec, err := s.store.Get(ctx, l.Name)
			if err != nil {
				s.log.Error("store read failed", "login", l.Name, "error", err.Error())
				return nil, nil, unavailableMint("the service logins could not be read")
			}
			candidates = append(candidates, sec)
		}
	}
	var found *state.Secret
	var foundSpec *login.Spec
	for _, sec := range candidates {
		text, err := textParams(sec.Params)
		if err != nil {
			continue
		}
		subject := text["subject"]
		if gen.login == "" && subject == "" {
			continue // by scope: only a login bound to a user
		}
		if subject != "" && subject != c.Owner() {
			if gen.login != "" {
				return nil, nil, refusedMint("the service login " + strconv.Quote(sec.Name) + " is another user's")
			}
			continue
		}
		if !mayUse(s, c, sec) {
			if gen.login != "" {
				return nil, nil, refusedMint("the caller may not use the service login " + strconv.Quote(sec.Name))
			}
			continue
		}
		spec, err := login.Parse(placeheld(text, sec), sec.Scope)
		if err != nil || !spec.Covers(consumer.Scope) {
			if gen.login != "" {
				return nil, nil, refusedMint("the secret's scope is outside the service login " + strconv.Quote(sec.Name))
			}
			continue
		}
		if found != nil {
			return nil, nil, refusedMint("more than one service login for the caller covers the secret's scope")
		}
		found, foundSpec = sec, spec
	}
	if found == nil {
		return nil, nil, refusedMint("no service login for the caller covers the secret's scope")
	}
	return found, foundSpec, nil
}

// placeheld: a login's params with its inputs stood in for, to read its shape (they are resolved at a login).
func placeheld(text map[string]string, sec *state.Secret) map[string]string {
	out := make(map[string]string, len(text))
	for k, v := range text {
		out[k] = v
		if isInput(k) && v != "" {
			out[k] = "x"
		}
	}
	return out
}

func mayUse(s *Server, c *auth.Caller, sec *state.Secret) bool {
	for _, v := range s.policy.Verbs(c, sec) {
		if v == "use" {
			return true
		}
	}
	return false
}

// loginResult: the login's result for the effective user - cached until shortly before it expires, renewed
// from what it kept, or a new login; one at a time per login and user in this replica.
func (s *Server) loginResult(r *http.Request, c *auth.Caller, sec *state.Secret, shape *login.Spec) (*login.Result, *mintProblem) {
	// per user when bound to one, or made of the user's claims (in any form): never shared across users
	userKey := ""
	text, _ := textParams(sec.Params)
	if text["subject"] != "" || len(claimKeys(sec.Params, s.material.Refs(sec.Params))) > 0 {
		userKey = c.Owner()
	}
	keyAt := func(version int64) string {
		return sec.Name + "\x00" + strconv.FormatInt(version, 10) + "\x00" + userKey
	}
	key := keyAt(sec.Version)
	lockKey := "login\x00" + sec.Name + "\x00" + userKey // not the version: a rotation moves it
	now := s.now()
	fresh := func(e *loginEntry) bool { return e != nil && e.result.Expiry.Sub(now) > mintMargin }
	s.logins.mu.Lock()
	if e := s.logins.entries[key]; fresh(e) {
		s.logins.mu.Unlock()
		return e.result, nil
	}
	s.logins.mu.Unlock()
	unlock, err := s.mintLocks.lock(r.Context(), lockKey)
	if err != nil {
		return nil, unavailableMint("the request ended while the service login was being renewed")
	}
	defer unlock()
	// read again under the lock: a rotation made meanwhile (here or by another replica) moved its version
	cur, err := s.store.Get(r.Context(), sec.Name)
	if err != nil || !isLogin(cur) {
		return nil, unavailableMint("the service login could not be read")
	}
	sec, key = cur, keyAt(cur.Version)
	s.logins.mu.Lock()
	prev := s.logins.entries[key]
	s.logins.mu.Unlock()
	if fresh(prev) {
		return prev.result, nil
	}
	spec, problem := s.loginSpec(r, c, sec)
	if problem != nil {
		return nil, problem
	}
	if spec.Flow == login.FlowRefresh && prev != nil && prev.kept["refresh_token"] != spec.RefreshToken {
		prev = nil // what is stored is newer than what this replica kept: renew from it
	}
	// detached from the request: a refresh token the service rotated must not be lost with a dropped connection
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), refreshTimeout)
	defer cancel()
	client := s.loginClient()
	var res *login.Result
	var kept map[string]string
	renewed := false
	if prev != nil {
		var ok bool
		res, kept, ok, err = client.Refresh(ctx, spec, prev.kept)
		renewed = ok && err == nil
		if ok && err != nil {
			s.log.Warn("a service login's refresh failed: logging in again", "login", sec.Name, "reason", err.Error())
		}
	}
	if renewed && kept["refresh_token"] == "" {
		kept = prev.kept // RFC 6749 6: a refresh may give no new refresh token - the old one stays good
	}
	if !renewed {
		res, kept, err = client.Login(ctx, spec)
	}
	if err != nil {
		s.log.Warn("a service login failed", "login", sec.Name, "reason", err.Error())
		var le *login.Error
		if errors.As(err, &le) && le.Refused {
			return nil, refusedMint("the service login " + strconv.Quote(sec.Name) + " was refused: " + le.Msg)
		}
		return nil, unavailableMint("the service login " + strconv.Quote(sec.Name) + " did not answer")
	}
	s.log.Info("service login", "login", sec.Name, "renewed", renewed)
	if spec.Flow == login.FlowRefresh && kept["refresh_token"] != "" && kept["refresh_token"] != spec.RefreshToken {
		// a rotated refresh token is written back (sealed, compare-and-set): the stored one is spent
		if version, err := s.rotateRefresh(ctx, sec, kept["refresh_token"]); err != nil {
			s.log.Error("a service login's rotated refresh token could not be stored: it lives in this replica only",
				"login", sec.Name, "error", err.Error())
		} else {
			key = keyAt(version) // the next read finds the login at its new version: served from here
		}
	}
	s.logins.mu.Lock()
	if s.logins.entries == nil {
		s.logins.entries = map[string]*loginEntry{}
	}
	for k, e := range s.logins.entries { // expired entries go - one that can be renewed after a while
		horizon := e.result.Expiry
		if e.kept["refresh_token"] != "" {
			horizon = horizon.Add(refreshHorizon)
		}
		if !horizon.After(now) {
			delete(s.logins.entries, k)
		}
	}
	s.logins.entries[key] = &loginEntry{result: res, kept: kept}
	s.logins.mu.Unlock()
	return res, nil
}

// errRotatedElsewhere: the login changed since it was read - another replica stored its own rotation, or an
// administrator wrote it.
var errRotatedElsewhere = errors.New("the service login changed meanwhile")

// rotateRefresh writes a login's rotated refresh token back, on the version it was read at; it gives the new
// version.
func (s *Server) rotateRefresh(ctx context.Context, sec *state.Secret, token string) (int64, error) {
	raw, _ := json.Marshal(token)
	saved, err := s.store.Update(ctx, sec.Name, func(cur *state.Secret) (*state.Secret, error) {
		if cur == nil {
			return nil, state.ErrNotFound
		}
		if cur.Version != sec.Version {
			return nil, errRotatedElsewhere
		}
		next := state.Clone(cur)
		next.Params["refresh_token"] = raw
		next.Version, next.UpdatedAt = cur.Version+1, s.now()
		return next, nil
	})
	if err != nil {
		return 0, err
	}
	return saved.Version, nil
}

// loginSpec: the login with its inputs resolved - references read with the service's identity, claims the
// effective user's.
func (s *Server) loginSpec(r *http.Request, c *auth.Caller, sec *state.Secret) (*login.Spec, *mintProblem) {
	withUser, problem := claimsIntoRefs(c, sec.Params, s.material.Refs(sec.Params))
	if problem != nil {
		return nil, problem
	}
	params, resolved, err := s.material.Resolve(r.Context(), withUser) // the allowlist again, the claim in
	if err != nil {
		s.log.Error("a service login's reference did not resolve", "login", sec.Name, "error", err.Error())
		return nil, unavailableMint("a reference of the service login did not resolve")
	}
	out := make(map[string]json.RawMessage, len(params))
	for k, v := range params {
		out[k] = v
	}
	refs := map[string]bool{}
	for _, res := range resolved {
		refs[res.Param] = true
	}
	withClaims := *sec
	withClaims.Dynamic = true // its claims are made for the user (checked at the write: claims only)
	if _, _, problem := s.generated(r, c, &withClaims, out, refs); problem != nil {
		return nil, problem
	}
	text, err := textParams(out)
	if err != nil {
		return nil, &mintProblem{http.StatusInternalServerError, "service_error", "the service login cannot be read: " + err.Error()}
	}
	spec, err := login.Parse(text, sec.Scope)
	if err != nil {
		return nil, &mintProblem{http.StatusInternalServerError, "service_error", "the service login cannot be read: " + err.Error()}
	}
	spec.Name = sec.Name
	return spec, nil
}

// adminLogins lists the service logins (the console's): descriptors, never their params.
func (s *Server) adminLogins(w http.ResponseWriter, r *http.Request) {
	listed, err := s.store.List(r.Context())
	if err != nil {
		s.unavailable(w, "read", "", err)
		return
	}
	out := []map[string]any{}
	for _, sec := range listed {
		if isLogin(sec) {
			out = append(out, descriptor(sec, s.policy.Verbs(callerOf(r), sec)))
		}
	}
	writeJSON(w, http.StatusOK, out)
}
