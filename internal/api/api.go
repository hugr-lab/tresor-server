// Package api is the duckdb-secrets/1 HTTP surface (tresor specs/003,
// website/docs/protocol.md). Every decision uses the caller's own principals - under a delegation grant, the
// actor's for `use` (specs/009); nothing here logs a token or a secret's material.
//
// Taken over from tresor's reference server at 6133d0d (MIT, the same owner; see NOTICE). specs/NNN here are
// tresor's specs; spec NNN (with a space) are this repository's.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hugr-lab/tresor-server/internal/auth"
	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/material"
	"github.com/hugr-lab/tresor-server/internal/state"
)

// Protocol is the discovery document's protocol string.
const Protocol = "duckdb-secrets/1"

// the per-secret verbs, in the protocol's order (specs/009): `use` from a grant to a role or group; the
// management verbs are the admins'
var (
	allVerbs    = []string{"use", "update", "delete", "annotate", "grant"}
	manageVerbs = []string{"update", "delete", "annotate", "grant"}
)

// Server serves the protocol.
type Server struct {
	cfg       *config.Config
	verifier  *auth.Verifier
	store     state.Store
	log       *slog.Logger
	now       func() time.Time
	direct    directCache        // tokens minted for callers reading directly (specs/010)
	mintLocks mintLocks          // one replica's renewals of a grant's token, per grant and audience
	material  *material.Resolver // references (ref+...): nil refuses them all
}

// New wires a server; the verifier and the store are the caller's. It reads the store once, to report
// grants from before specs/009.
func New(ctx context.Context, cfg *config.Config, verifier *auth.Verifier, st state.Store, log *slog.Logger, opts ...Option) (*Server, error) {
	s := &Server{cfg: cfg, verifier: verifier, store: st, log: log, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	secrets, err := st.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("the state store: %w", err)
	}
	// a store from before specs/009 may hold grants the model no longer honours: say so, once, by name
	for _, sec := range secrets {
		for _, g := range sec.Grants {
			if !roleOrGroup(g.Principal) || !slices.Equal(g.Verbs, []string{"use"}) {
				log.Warn("a grant from before specs/009 is ignored: grants give use to roles and groups only",
					"secret", sec.Name, "grant", g.ID)
			}
		}
	}
	return s, nil
}

// Option configures a server.
type Option func(*Server)

// WithMaterial lets secrets hold references (spec 002), resolved by r.
func WithMaterial(r *material.Resolver) Option { return func(s *Server) { s.material = r } }

// Handler returns the routes, under the path of public_url (a service may live below a base path: the
// client asks <base>/.well-known/duckdb-secrets and appends /v1/... to `api`).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/duckdb-secrets", s.discovery)
	mux.HandleFunc("GET /v1/whoami", s.authed(s.whoami))
	mux.HandleFunc("GET /v1/secrets", s.authed(s.listSecrets))
	mux.HandleFunc("GET /v1/secrets/{name}", s.authed(s.getSecret))
	mux.HandleFunc("PUT /v1/secrets/{name}", s.authed(s.putSecret))
	mux.HandleFunc("DELETE /v1/secrets/{name}", s.authed(s.deleteSecret))
	mux.HandleFunc("PATCH /v1/secrets/{name}", s.authed(s.patchSecret))
	mux.HandleFunc("GET /v1/secrets/{name}/grants", s.authed(s.listGrants))
	mux.HandleFunc("PUT /v1/secrets/{name}/grants/{id}", s.authed(s.putGrant))
	mux.HandleFunc("DELETE /v1/secrets/{name}/grants/{id}", s.authed(s.deleteGrant))
	// spec 004 (tresor spec 018): variables - the secrets' rules (names, grants, conditional writes), their own
	// namespace, chosen by the route matched (of)
	mux.HandleFunc("GET /v1/variables", s.authed(s.listVariables))
	mux.HandleFunc("GET /v1/variables/{name}", s.authed(s.getVariable))
	mux.HandleFunc("PUT /v1/variables/{name}", s.authed(s.putVariable))
	mux.HandleFunc("DELETE /v1/variables/{name}", s.authed(s.deleteSecret))
	mux.HandleFunc("PATCH /v1/variables/{name}", s.authed(s.patchSecret))
	mux.HandleFunc("GET /v1/variables/{name}/grants", s.authed(s.listGrants))
	mux.HandleFunc("PUT /v1/variables/{name}/grants/{id}", s.authed(s.putGrant))
	mux.HandleFunc("DELETE /v1/variables/{name}/grants/{id}", s.authed(s.deleteGrant))
	mux.HandleFunc("POST /v1/delegations", s.authed(s.exchange))
	mux.HandleFunc("DELETE /v1/delegations/{id}", s.authed(s.revokeGrant))
	mux.HandleFunc("DELETE /v1/delegations", s.authed(s.revokeGrants))
	// anything else - an unknown path, a known path with another method - is a problem document too
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		problem(w, http.StatusNotFound, "not_found", "no such resource: "+r.Method+" "+r.URL.Path)
	})
	var h http.Handler = mux
	if u, err := url.Parse(s.cfg.PublicURL); err == nil && strings.TrimRight(u.Path, "/") != "" {
		h = http.StripPrefix(strings.TrimRight(u.Path, "/"), mux)
	}
	return s.logged(h)
}

// --- plumbing --------------------------------------------------------------------------------------

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

type callerKey struct{}

func callerOf(r *http.Request) *auth.Caller {
	c, _ := r.Context().Value(callerKey{}).(*auth.Caller)
	return c
}

// logged is the request log: method, path, status, subject - never a header or a body.
func (s *Server) logged(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		start := time.Now()
		holder := &auth.Caller{}
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), loggedCallerKey{}, holder)))
		attrs := []any{"method", r.Method, "path", loggedPath(r.URL.Path), "status", rec.status,
			"subject", holder.Subject, "ms", time.Since(start).Milliseconds()}
		// the caller's trace (protocol, Tracing): its ids, so the line can be found from the client's trace
		if traceID, spanID, ok := traceIDs(r.Header.Get("traceparent")); ok {
			attrs = append(attrs, "trace_id", traceID, "parent_span_id", spanID)
		}
		s.log.Info("request", attrs...)
	})
}

// traceIDs reads a W3C traceparent (version 00): the trace id and the parent span id; ok false for anything
// malformed, which is then ignored - never logged as it came.
func traceIDs(header string) (traceID, spanID string, ok bool) {
	parts := strings.Split(header, "-")
	if len(header) != 55 || len(parts) != 4 || parts[0] != "00" || !lowerHex(parts[1], 32) ||
		!lowerHex(parts[2], 16) || !lowerHex(parts[3], 2) {
		return "", "", false
	}
	if parts[1] == strings.Repeat("0", 32) || parts[2] == strings.Repeat("0", 16) {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func lowerHex(text string, size int) bool {
	if len(text) != size {
		return false
	}
	for _, c := range text {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

type loggedCallerKey struct{}

// loggedPath is a request's path as logged: a delegation grant's id is a bearer credential, so the path
// that names one (DELETE /v1/delegations/{id}) is logged without it.
func loggedPath(path string) string {
	if i := strings.Index(path, "/v1/delegations/"); i >= 0 {
		return path[:i] + "/v1/delegations/…"
	}
	return path
}

// authed verifies the bearer token; a failure is 401 unauthenticated with the reason in the log only.
func (s *Server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// the scheme is case-insensitive (RFC 9110 §11.1)
		header := r.Header.Get("Authorization")
		scheme, raw, ok := strings.Cut(header, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(raw) == "" {
			problem(w, http.StatusUnauthorized, "unauthenticated", "a bearer token is required")
			return
		}
		caller, err := s.verifier.Verify(r.Context(), strings.TrimSpace(raw))
		if err != nil {
			s.log.Warn("token refused", "reason", err.Error())
			problem(w, http.StatusUnauthorized, "unauthenticated", "token missing, invalid or expired")
			return
		}
		if r.Header.Get("Delegation") != "" {
			// a server acting for a user: its own token proved who it is, the grant says for whom
			user, gr, err := s.delegated(r, caller)
			if errors.Is(err, errGrantStore) {
				grantStoreProblem(w, err, "the delegation grant could not be read")
				return
			}
			if err != nil {
				s.log.Warn("delegation refused", "actor", caller.Owner(), "reason", err.Error())
				problem(w, http.StatusUnauthorized, "unauthenticated", "the delegation grant is not valid for this caller")
				return
			}
			caller = user
			r = r.WithContext(context.WithValue(r.Context(), grantKey{}, gr))
		}
		if holder, ok := r.Context().Value(loggedCallerKey{}).(*auth.Caller); ok {
			subject := caller.Owner() // never the grant id
			if caller.Actor != "" {
				subject += " via " + caller.Actor
			}
			*holder = auth.Caller{Subject: subject}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, caller)))
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// problem is an RFC 9457 error with a type from the protocol's list.
func problem(w http.ResponseWriter, status int, kind, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": kind, "title": kind, "status": status, "detail": detail})
}

// readJSON reads one JSON document of at most 1 MiB, with no unknown fields and nothing after it.
func readJSON(r *http.Request, into any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil {
		return err
	}
	if len(body) > 1<<20 {
		return errors.New("the body is larger than 1 MiB")
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after the JSON document")
	}
	return nil
}

// --- permissions ------------------------------------------------------------------------------------

func (s *Server) isAdmin(c *auth.Caller) bool {
	return slices.ContainsFunc(s.cfg.Policy.Admins, c.Has)
}

// verbs is what the caller may do with sec (specs/009): `use` when a grant names one of its roles or groups,
// and the management verbs for an admin (an admin role implies no `use`). Under a delegation grant `use` is
// the ACTOR's (a user gets nothing beyond what the server was granted), and a management verb passes only
// for a user who is an admin, when the actor policy lists it - administration through a duckdb-acl node.
func (s *Server) verbs(c *auth.Caller, sec *state.Secret) []string {
	out := []string{} // a list, never null
	if c.Actor != "" {
		allowed := s.actorVerbs(c.Actor, c.ActorIssuer)
		if slices.Contains(allowed, "use") && usable(sec, c.ActorPrincipals) {
			out = append(out, "use")
		}
		// administration through a server: the user's own admin role, and the verbs the policy lets it pass on
		if s.isAdmin(c) {
			for _, v := range manageVerbs {
				if slices.Contains(allowed, v) {
					out = append(out, v)
				}
			}
		}
		return out
	}
	if usable(sec, c.Principals) {
		out = append(out, "use")
	}
	if s.isAdmin(c) {
		out = append(out, manageVerbs...)
	}
	return out
}

// usable: a grant gives `use` to one of these principals - a role: or group: grant only. A grant a store kept
// from before specs/009 (to a subject: or a client:, or of other verbs) gives nothing: it is reported at
// start and ignored.
func usable(sec *state.Secret, principals []string) bool {
	for _, g := range sec.Grants {
		if roleOrGroup(g.Principal) && slices.Contains(g.Verbs, "use") && slices.Contains(principals, g.Principal) {
			return true
		}
	}
	return false
}

func roleOrGroup(p string) bool {
	role, isRole := strings.CutPrefix(p, "role:")
	group, isGroup := strings.CutPrefix(p, "group:")
	return (isRole && role != "") || (isGroup && group != "")
}

// mayCreate: only admins create - through a server too, when the actor policy lists `create`.
func (s *Server) mayCreate(c *auth.Caller, name string) bool {
	if !s.isAdmin(c) {
		return false
	}
	return c.Actor == "" || slices.Contains(s.actorVerbs(c.Actor, c.ActorIssuer), "create")
}

// visible fetches a secret the caller holds any verb on (under a grant: the actor's use, an admin's management
// through it); an invisible one is the same 404 as a missing one, so a name's existence does not leak. A secret
// that does not verify (the Kubernetes store) is 500 to an administrator only: no one else can be shown to hold
// a verb on it.
func (s *Server) visible(w http.ResponseWriter, r *http.Request, c *auth.Caller, name string) (*state.Secret, []string, bool) {
	ns, kind := s.of(r)
	sec, err := ns.Describe(r.Context(), name) // no material: a permission needs none
	if errors.Is(err, keys.ErrSealed) && !s.isAdmin(c) {
		s.log.Error("store read failed", kind, name, "error", err.Error())
		err = state.ErrNotFound
	}
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		s.unavailable(w, "read", name, err)
		return nil, nil, false
	}
	if err == nil {
		verbs := s.verbs(c, sec)
		if len(verbs) > 0 {
			return sec, verbs, true
		}
	}
	problem(w, http.StatusNotFound, "not_found", fmt.Sprintf("no %s %q", kind, name))
	return nil, nil, false
}

// of answers the namespace a request addresses (spec 004), and what to call one of its entries - from the route
// it matched, never from its path: a secret's name may hold "/v1/variables" (percent-encoded on the wire).
func (s *Server) of(r *http.Request) (state.Store, string) {
	if strings.Contains(r.Pattern, " /v1/variables") {
		return s.store.Variables(), "variable"
	}
	return s.store, "secret"
}

// describe is an entry as the protocol describes it: a secret's descriptor, or a variable's.
func (s *Server) describe(r *http.Request, sec *state.Secret, verbs []string) map[string]any {
	if _, kind := s.of(r); kind == "variable" {
		return variableDescriptor(sec, verbs)
	}
	return descriptor(sec, verbs)
}

// unavailable answers a store that failed: 503, the reason in the log only. A secret too large for the store
// is the caller's: 422.
//
// A value that does not open (keys.ErrSealed: its key changed, or it was tampered with) is no outage:
// 500 service_error - trying again will not help until an operator acts (protocol, Errors; tresor spec 016).
func (s *Server) unavailable(w http.ResponseWriter, what, name string, err error) {
	if errors.Is(err, state.ErrTooLarge) {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", err.Error())
		return
	}
	s.log.Error("store "+what+" failed", "secret", name, "error", err.Error())
	if errors.Is(err, keys.ErrSealed) {
		problem(w, http.StatusInternalServerError, "service_error", "a value the service holds does not open")
		return
	}
	problem(w, http.StatusServiceUnavailable, "service_unavailable", "the store could not be "+what)
}

// --- discovery and identity ------------------------------------------------------------------------

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	issuers := make([]map[string]any, 0, len(s.cfg.Issuers))
	for _, is := range s.cfg.Issuers {
		entry := map[string]any{"issuer": is.Issuer, "audience": is.Audience}
		if is.ClientID != "" {
			entry["client_id"] = is.ClientID
		}
		if is.Scopes != nil {
			entry["scopes"] = is.Scopes
		}
		if is.HumanFlows != nil {
			entry["human_flows"] = is.HumanFlows
		}
		if is.ServiceFlows != nil {
			entry["service_flows"] = is.ServiceFlows
		}
		if is.AudienceParameter {
			entry["audience_parameter"] = true
		}
		issuers = append(issuers, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"protocol": Protocol,
		"api":      strings.TrimRight(s.cfg.PublicURL, "/"),
		"issuers":  issuers,
		"capabilities": map[string]bool{
			"write": true, "annotate": true, "dynamic": false, "delegation": true, "variables": true,
		},
	})
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	// only admins create (specs/009) - through a server only if its actor policy lists create
	create := s.mayCreate(c, "")
	roles := []string{}
	for _, p := range c.Principals {
		if !strings.HasPrefix(p, "subject:") {
			roles = append(roles, p)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":      c.Issuer,
		"subject":     c.Subject,
		"roles":       roles,
		"actor":       nilIfEmpty(c.Actor),
		"expires_at":  c.ExpiresAt.UTC().Format(time.RFC3339),
		"permissions": map[string]any{"create": create},
	})
}

func nilIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// --- secrets -----------------------------------------------------------------------------------------

func descriptor(sec *state.Secret, verbs []string) map[string]any {
	if verbs == nil {
		verbs = []string{}
	}
	scope := sec.Scope
	if scope == nil {
		scope = []string{}
	}
	return map[string]any{
		"name":        sec.Name,
		"type":        sec.Type,
		"provider":    sec.Provider,
		"scope":       scope,
		"comment":     sec.Comment,
		"owner":       sec.Owner,
		"created_at":  sec.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":  sec.UpdatedAt.UTC().Format(time.RFC3339),
		"version":     strconv.FormatInt(sec.Version, 10),
		"dynamic":     isMinted(sec), // a token minted per caller (specs/010)
		"permissions": verbs,
	}
}

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	typ := r.URL.Query().Get("type")
	secrets, err := s.store.List(r.Context())
	if err != nil {
		s.unavailable(w, "read", "", err)
		return
	}
	out := []map[string]any{}
	for _, sec := range secrets {
		if typ != "" && !strings.EqualFold(sec.Type, typ) {
			continue
		}
		if verbs := s.verbs(c, sec); len(verbs) > 0 {
			out = append(out, descriptor(sec, verbs))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getSecret(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	sec, verbs, ok := s.visible(w, r, c, r.PathValue("name"))
	if !ok {
		return
	}
	if !slices.Contains(verbs, "use") {
		s.refuse(w, c, "use")
		return
	}
	// the material, now that the caller may use it
	full, err := s.store.Get(r.Context(), sec.Name)
	if errors.Is(err, state.ErrNotFound) { // dropped meanwhile
		problem(w, http.StatusNotFound, "not_found", fmt.Sprintf("no secret %q", sec.Name))
		return
	}
	if err != nil {
		s.unavailable(w, "read", sec.Name, err)
		return
	}
	sec = full
	body := descriptor(sec, verbs)
	// references are read now, with the service's identity: a rotation in the vault reaches DuckDB at its next
	// fetch; one that does not resolve fails this fetch - never an empty or a stale value
	params, resolved, err := s.material.Resolve(r.Context(), sec.Params)
	if err != nil {
		s.log.Error("a reference did not resolve", "secret", sec.Name, "error", err.Error())
		problem(w, http.StatusServiceUnavailable, "service_unavailable", "a reference of the secret did not resolve")
		return
	}
	for _, res := range resolved { // where and which version, never the value
		s.log.Info("reference resolved", "secret", sec.Name, "param", res.Param, "ref", res.Ref.String(),
			"version", res.Version)
	}
	if params == nil {
		params = map[string]json.RawMessage{}
	}
	redact := sec.RedactKeys
	if redact == nil {
		redact = []string{}
	}
	body["params"] = params
	body["redact_keys"] = redact
	body["expires_at"] = nil
	if isMinted(sec) {
		// a token for the caller (specs/010): the caller's own, or under a grant the grant's user's
		token, refusal := s.mintedToken(r, c, sec)
		if refusal != nil {
			problem(w, refusal.status, refusal.kind, refusal.detail)
			return
		}
		param := tokenParam[strings.ToLower(sec.Type)]
		minted := make(map[string]json.RawMessage, len(params)+1)
		for k, v := range params {
			minted[k] = v
		}
		minted[param], _ = json.Marshal(token.Access)
		body["params"] = minted
		body["redact_keys"] = append(slices.Clone(redact), param)
		if !token.Expiry.IsZero() {
			body["expires_at"] = token.Expiry.UTC().Format(time.RFC3339)
		}
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(sec.Version, 10)))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, body)
}

type secretBody struct {
	Type       string                     `json:"type"`
	Provider   string                     `json:"provider"`
	Scope      []string                   `json:"scope"`
	Params     map[string]json.RawMessage `json:"params"`
	RedactKeys []string                   `json:"redact_keys"`
	Comment    *string                    `json:"comment"`
}

// validParams: every value a string or {type, value} (protocol, Material).
// duplicateKeys says whether a JSON object repeats a key (a map keeps only one of them).
func duplicateKeys(raw json.RawMessage) bool {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return true
		}
		k, _ := t.(string)
		if seen[k] {
			return true
		}
		seen[k] = true
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return true
		}
	}
	return false
}

func validParams(params map[string]json.RawMessage, redact []string) error {
	for key, raw := range params {
		if key == "" {
			return errors.New("an empty parameter name")
		}
		if strings.TrimSpace(string(raw)) == "null" {
			return fmt.Errorf("parameter %q is null", key)
		}
		var str string
		if json.Unmarshal(raw, &str) == nil {
			continue
		}
		// exactly the keys type and value, as written: Go's decoder would match "VALUE" too, and take the last
		// of repeated keys - a shape a client reads otherwise than this service
		var typed map[string]json.RawMessage
		if json.Unmarshal(raw, &typed) != nil || len(typed) != 2 || typed["type"] == nil || typed["value"] == nil {
			return fmt.Errorf("parameter %q is neither a string nor {type, value}", key)
		}
		var typ string
		if json.Unmarshal(typed["type"], &typ) != nil || typ == "" || string(typed["value"]) == "null" ||
			duplicateKeys(raw) {
			return fmt.Errorf("parameter %q is neither a string nor {type, value}", key)
		}
	}
	for _, k := range redact {
		if _, ok := params[k]; !ok {
			return fmt.Errorf("redact key %q is not a parameter", k)
		}
	}
	return nil
}

// maxNameLength bounds a secret's name and a grant's id, in characters: every store keeps them, SQL Server in
// an index key.
const maxNameLength = 200

// validName checks a secret's name or a grant's id as written (spec 002), as the protocol lets a service refuse
// one (General, names; tresor spec 016): empty, over 200 code points, not UTF-8, edge whitespace
// (unicode.IsSpace - SQL Server compares 'a' and 'a ' as equal), a control character (unicode.IsControl: C0,
// DEL, C1). The error names the rule, not the name.
func validName(what, name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%s is empty", what)
	case utf8.RuneCountInString(name) > maxNameLength:
		return fmt.Errorf("%s is longer than %d characters", what, maxNameLength)
	case !utf8.ValidString(name):
		return fmt.Errorf("%s is not UTF-8", what)
	case strings.TrimSpace(name) != name:
		return fmt.Errorf("%s begins or ends with whitespace", what)
	case strings.IndexFunc(name, unicode.IsControl) >= 0:
		return fmt.Errorf("%s holds a control character", what)
	}
	return nil
}

func (s *Server) putSecret(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	name := r.PathValue("name")
	if err := validName("the name", name); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", err.Error())
		return
	}
	var body secretBody
	if err := readJSON(r, &body); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "the body is not a secret: "+err.Error())
		return
	}
	if body.Type == "" {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "type is required")
		return
	}
	if err := validParams(body.Params, body.RedactKeys); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", err.Error())
		return
	}
	if body.Provider == tokenExchangeProvider {
		if err := s.validMinted(body.Type, body.Params); err != nil {
			problem(w, http.StatusUnprocessableEntity, "invalid_secret", err.Error())
			return
		}
	}
	// references (ref+...): to a configured source, within its allowlist, VARCHAR only - never stored as a
	// literal - and redacted: a resolved value never shows in duckdb_secrets()
	redact, err := s.material.CheckWrite(body.Provider, body.Params, body.RedactKeys)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", err.Error())
		return
	}
	body.RedactKeys = redact
	now := s.now()
	s.upsert(w, r, name, func() *state.Secret {
		return &state.Secret{
			Type: body.Type, Provider: body.Provider, Scope: body.Scope, Params: body.Params,
			RedactKeys: body.RedactKeys, Comment: deref(body.Comment), Owner: c.Owner(),
			CreatedAt: now, UpdatedAt: now, Version: 1,
		}
	}, func(next *state.Secret) {
		next.Type, next.Provider, next.Scope = body.Type, body.Provider, body.Scope
		next.Params, next.RedactKeys = body.Params, body.RedactKeys
		if body.Comment != nil {
			next.Comment = *body.Comment
		}
	})
}

// upsert is a PUT of a secret or a variable (spec 004): created under the caller's create, or replaced under
// its update, as the preconditions allow. If-None-Match: "*" (CREATE) fails on any existing entry; with an
// ETag, on that version only. created builds a new entry; change applies the body to a copy.
func (s *Server) upsert(w http.ResponseWriter, r *http.Request, name string, created func() *state.Secret,
	change func(next *state.Secret)) {
	c := callerOf(r)
	ns, _ := s.of(r)
	ifNoneMatch := strings.TrimSpace(r.Header.Get("If-None-Match"))
	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	type refusal struct {
		status       int
		kind, detail string
	}
	var refused *refusal
	now := s.now()
	isNew := false
	saved, err := ns.Update(r.Context(), name, func(current *state.Secret) (*state.Secret, error) {
		refused, isNew = nil, false // fn may run again, on a fresher secret (state.Store)
		if current == nil {
			if !s.mayCreate(c, name) {
				kind := "no_verb"
				if c.Actor != "" {
					kind = "actor_not_allowed"
				}
				refused = &refusal{http.StatusForbidden, kind, "the caller may not create " + strconv.Quote(name)}
				return nil, errors.New("refused")
			}
			if ifMatch != "" { // after the permission: a precondition must not tell a name exists
				return nil, errPrecondition
			}
			isNew = true
			return created(), nil
		}
		verbs := s.verbs(c, current)
		if len(verbs) == 0 || (!slices.Contains(verbs, "update") && !s.mayCreate(c, name)) {
			// invisible, or not ours to create: the same answer as for a missing name the caller may not
			// create - neither tells that the name exists
			kind := "no_verb"
			if c.Actor != "" {
				kind = "actor_not_allowed"
			}
			refused = &refusal{http.StatusForbidden, kind, "the caller may not create " + strconv.Quote(name)}
			return nil, errors.New("refused")
		}
		currentTag := strconv.Quote(strconv.FormatInt(current.Version, 10))
		if ifNoneMatch == "*" || (ifNoneMatch != "" && ifNoneMatch == currentTag) {
			return nil, errPrecondition
		}
		if ifMatch != "" && ifMatch != currentTag && ifMatch != "*" {
			return nil, errPrecondition
		}
		if !slices.Contains(verbs, "update") {
			kind := "no_verb"
			if c.Actor != "" {
				kind = "actor_not_allowed" // through a server only for admins, as its policy lists (specs/009)
			}
			refused = &refusal{http.StatusForbidden, kind, "the caller's roles do not hold update"}
			return nil, errors.New("refused")
		}
		next := *current
		change(&next)
		next.UpdatedAt = now
		next.Version++
		return &next, nil
	})
	switch {
	case refused != nil:
		problem(w, refused.status, refused.kind, refused.detail)
	case errors.Is(err, errPrecondition):
		problem(w, http.StatusPreconditionFailed, "precondition_failed", "If-None-Match / If-Match not met")
	case err != nil:
		s.unavailable(w, "written", name, err)
	default:
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(saved.Version, 10)))
		status := http.StatusOK
		if isNew {
			status = http.StatusCreated
		}
		writeJSON(w, status, s.describe(r, saved, s.verbs(c, saved)))
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// mutate runs a change that needs `verb` on a visible secret; fn may refuse with a problem of its own.
func (s *Server) mutate(w http.ResponseWriter, r *http.Request, verb string,
	fn func(current *state.Secret) (*state.Secret, error)) (*state.Secret, bool) {
	c := callerOf(r)
	name := r.PathValue("name")
	ns, kind := s.of(r)
	var missing, forbidden bool
	saved, err := ns.Update(r.Context(), name, func(current *state.Secret) (*state.Secret, error) {
		missing, forbidden = false, false // fn may run again, on a fresher secret (state.Store)
		if current == nil {
			missing = true
			return nil, state.ErrNotFound
		}
		verbs := s.verbs(c, current)
		if len(verbs) == 0 {
			missing = true
			return nil, state.ErrNotFound
		}
		if !slices.Contains(verbs, verb) {
			forbidden = true
			return nil, errors.New("refused")
		}
		return fn(current)
	})
	switch {
	case missing:
		problem(w, http.StatusNotFound, "not_found", fmt.Sprintf("no %s %q", kind, name))
	case forbidden:
		s.refuse(w, c, verb)
	case errors.Is(err, errNotHeld):
		problem(w, http.StatusForbidden, "no_verb", strings.TrimPrefix(err.Error(), errNotHeld.Error()+": "))
	case errors.Is(err, errInvalid):
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", strings.TrimPrefix(err.Error(), errInvalid.Error()+": "))
	case errors.Is(err, state.ErrNotFound):
		problem(w, http.StatusNotFound, "not_found", "no such grant")
	case errors.Is(err, keys.ErrSealed) && !s.isAdmin(c) && !errors.Is(err, errInvalid):
		// a secret that does not verify, to a caller who cannot be shown to hold a verb on it: as missing
		s.log.Error("store write failed", kind, name, "error", err.Error())
		problem(w, http.StatusNotFound, "not_found", fmt.Sprintf("no %s %q", kind, name))
	case err != nil:
		s.unavailable(w, "written", name, err)
	default:
		return saved, true
	}
	return nil, false
}

var (
	errInvalid      = errors.New("invalid")
	errNotHeld      = errors.New("not held")
	errPrecondition = errors.New("precondition failed")
)

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.mutate(w, r, "delete", func(*state.Secret) (*state.Secret, error) { return nil, nil }); ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) patchSecret(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Comment *string `json:"comment"`
	}
	if err := readJSON(r, &body); err != nil || body.Comment == nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "PATCH takes {\"comment\": \"...\"}")
		return
	}
	now := s.now()
	saved, ok := s.mutate(w, r, "annotate", func(current *state.Secret) (*state.Secret, error) {
		current.Comment = *body.Comment
		current.UpdatedAt = now
		current.Version++
		return current, nil
	})
	if ok {
		writeJSON(w, http.StatusOK, s.describe(r, saved, s.verbs(callerOf(r), saved)))
	}
}

// --- grants ------------------------------------------------------------------------------------------

func grantList(sec *state.Secret) []state.Grant {
	if sec.Grants == nil {
		return []state.Grant{}
	}
	return sec.Grants
}

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	sec, verbs, ok := s.visible(w, r, callerOf(r), r.PathValue("name"))
	if !ok {
		return
	}
	if !slices.Contains(verbs, "grant") {
		s.refuse(w, callerOf(r), "grant")
		return
	}
	writeJSON(w, http.StatusOK, grantList(sec))
}

func (s *Server) putGrant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Principal string   `json:"principal"`
		Verbs     []string `json:"verbs"`
	}
	if err := readJSON(r, &body); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "a grant is {principal, verbs[]}")
		return
	}
	id := r.PathValue("id")
	if err := validName("the grant's id", id); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", err.Error())
		return
	}
	saved, ok := s.mutate(w, r, "grant", func(current *state.Secret) (*state.Secret, error) {
		// a grant gives `use` to a role or a group (specs/009): never one user, never a management verb
		role, isRole := strings.CutPrefix(body.Principal, "role:")
		group, isGroup := strings.CutPrefix(body.Principal, "group:")
		if !(isRole && role != "") && !(isGroup && group != "") {
			return nil, fmt.Errorf("%w: a grant names a role: or a group: principal", errInvalid)
		}
		if len(body.Verbs) != 1 || body.Verbs[0] != "use" {
			return nil, fmt.Errorf("%w: a grant gives use, and only use", errInvalid)
		}
		grant := state.Grant{ID: id, Principal: body.Principal, Verbs: body.Verbs}
		replaced := false
		for i := range current.Grants {
			if current.Grants[i].ID == id {
				current.Grants[i] = grant
				replaced = true
			}
		}
		if !replaced {
			current.Grants = append(current.Grants, grant)
		}
		current.Version++
		current.UpdatedAt = s.now()
		return current, nil
	})
	if ok {
		writeJSON(w, http.StatusOK, grantList(saved))
	}
}

func (s *Server) deleteGrant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, ok := s.mutate(w, r, "grant", func(current *state.Secret) (*state.Secret, error) {
		kept := current.Grants[:0]
		found := false
		for _, g := range current.Grants {
			if g.ID == id {
				found = true
				continue
			}
			kept = append(kept, g)
		}
		if !found {
			return nil, state.ErrNotFound
		}
		current.Grants = kept
		current.Version++
		current.UpdatedAt = s.now()
		return current, nil
	})
	if ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

func validPrincipal(p string) bool {
	for _, prefix := range []string{"role:", "group:", "subject:", "client:"} {
		if strings.HasPrefix(p, prefix) && len(p) > len(prefix) {
			return true
		}
	}
	return false
}
