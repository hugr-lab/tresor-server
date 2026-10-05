package api

// The console's own API (spec 010): /admin/v1, tresor-server's, not duckdb-secrets/1. Administrators only, never
// through a delegation grant; every request audited. It gives what the protocol does not: a secret's shape (names,
// types, which are secret, references as written - never a secret's value, never what a reference holds), the
// values of the parameters not marked secret on request, a replace that keeps values the administrator never saw,
// grants by principal, the references check, and the service as it runs.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hugr-lab/tresor-server/internal/audit"
	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/material"
	"github.com/hugr-lab/tresor-server/internal/refscheck"
	"github.com/hugr-lab/tresor-server/internal/state"
)

// Console is what the console's routes need of the running service.
type Console struct {
	UI      http.Handler                              // GET /ui/...: the build (web/console)
	Version string                                    // the build's version
	KEK     func(ctx context.Context) (string, error) // the KEK's current version id; nil: none (memory)
	Ready   func() (bool, map[string]string)          // readiness, each check's state
}

// WithConsole serves the console (spec 010): /ui/ and /admin/v1.
func WithConsole(c Console) Option { return func(s *Server) { s.console = &c } }

// refsCheckTime bounds an HTTP references check with reads (a source per reference, each bounded on its own).
const refsCheckTime = 10 * time.Minute

func (s *Server) consoleRoutes(mux *http.ServeMux) {
	mux.Handle("GET /ui/", s.console.UI)
	mux.Handle("GET /ui", s.console.UI)
	mux.HandleFunc("GET /admin/v1/service", s.authed(s.admin(s.adminService)))
	mux.HandleFunc("GET /admin/v1/secrets/{name}/shape", s.authed(s.admin(s.adminShape)))
	mux.HandleFunc("GET /admin/v1/variables/{name}/shape", s.authed(s.admin(s.adminShape)))
	mux.HandleFunc("PATCH /admin/v1/secrets/{name}/params", s.authed(s.admin(s.adminParams)))
	mux.HandleFunc("GET /admin/v1/grants", s.authed(s.admin(s.adminGrants)))
	mux.HandleFunc("POST /admin/v1/refs-check", s.authed(s.admin(s.adminRefsCheck)))
}

// admin lets administrators through, calling directly: never a server acting for one (a delegation grant).
func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := callerOf(r)
		w.Header().Set("Cache-Control", "no-store")
		if c.Actor != "" {
			problem(w, http.StatusForbidden, "actor_not_allowed", "the console's API is not for a server acting for a user")
			return
		}
		if !s.isAdmin(c) {
			problem(w, http.StatusForbidden, "no_verb", "the console is for administrators")
			return
		}
		next(w, r)
	}
}

// --- the service ---------------------------------------------------------------------------------------

func (s *Server) adminService(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg
	issuers := []map[string]any{}
	for _, is := range cfg.Issuers {
		entry := map[string]any{"issuer": is.Issuer, "audience": is.Audience}
		if is.ClientID != "" {
			entry["client_id"] = is.ClientID
		}
		if ex := is.Exchange; ex != nil {
			entry["exchange"] = map[string]any{"client_id": ex.ClientID, "client_auth": ex.ClientAuth}
		}
		issuers = append(issuers, entry)
	}
	sources := []map[string]any{}
	for _, src := range cfg.Sources() {
		sources = append(sources, map[string]any{"name": src.Name, "kind": src.Kind, "named": src.Named,
			"connection": connection(src), "allow": allowlist(src), "cache_ttl": cacheTTL(src).String()})
	}
	kek := map[string]any{"kind": cfg.Keys.Kind}
	if s.console.KEK != nil {
		if current, err := s.console.KEK(r.Context()); err == nil {
			kek["current"] = current
		} else {
			kek["error"] = "the KEK did not answer" // the reason is in the log
			s.log.Warn("the KEK's current version", "error", err.Error())
		}
	}
	ready, checks := true, map[string]string{}
	if s.console.Ready != nil {
		ready, checks = s.console.Ready()
	}
	actors := []map[string]any{}
	for _, a := range cfg.Policy.Actors {
		actors = append(actors, map[string]any{"principal": a.Principal, "verbs": a.Verbs})
	}
	auditLevel := cfg.Audit.Level
	if auditLevel == "" {
		auditLevel = "all"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.console.Version, "protocol": Protocol, "environment": cfg.UI.Environment,
		"capabilities": []string{"write", "annotate", "delegation", "variables", "token_exchange"},
		"state":        cfg.State.Kind, "kek": kek, "issuers": issuers, "sources": sources,
		"policy": map[string]any{"admins": cfg.Policy.Admins, "actors": actors},
		"audit":  auditLevel,
		"ready":  map[string]any{"ready": ready, "checks": checks},
	})
}

// connection is where a source reads, as an administrator may see it: an address and a login method, never a
// token, a key or a file's content.
func connection(src config.Source) string {
	switch src.Kind {
	case "vault":
		return src.Vault.Address + " · " + src.Vault.Auth.Method
	case "azkv":
		c := "azure " + src.Azure.Identity
		if src.Azure.TenantID != "" {
			c += " · tenant " + src.Azure.TenantID
		}
		return c
	case "k8s":
		return "this cluster"
	}
	return ""
}

func allowlist(src config.Source) []string {
	out := []string{}
	place := func(where string, prefixes []string) {
		if len(prefixes) == 0 {
			out = append(out, where+"/*")
		}
		for _, p := range prefixes {
			out = append(out, where+"/"+p+"*")
		}
	}
	for _, a := range src.VaultAllow.Allow {
		place(a.Mount, a.Prefixes)
	}
	for _, a := range src.AzKV.Allow {
		place(a.Vault, a.Prefixes)
	}
	for _, a := range src.K8s.Allow {
		place(a.Namespace, a.Prefixes)
	}
	return out
}

func cacheTTL(src config.Source) time.Duration {
	switch src.Kind {
	case "vault":
		return src.VaultAllow.CacheTTL
	case "azkv":
		return src.AzKV.CacheTTL
	}
	return 0
}

// --- an entry's shape ------------------------------------------------------------------------------------

// shapeParam is one parameter as the console shows it: Value only when asked, and only for a parameter that is
// neither marked secret nor a reference.
type shapeParam struct {
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Redacted  bool            `json:"redacted"`
	Reference string          `json:"reference,omitempty"`
	Value     json.RawMessage `json:"value,omitempty"`
}

func (s *Server) adminShape(w http.ResponseWriter, r *http.Request) {
	ns, kind := s.of(r)
	name := r.PathValue("name")
	values := r.URL.Query().Get("values") == "1"
	o := observed(r)
	if values {
		o.kind = audit.KindReveal
	}
	sec, err := ns.Get(r.Context(), name)
	if errors.Is(err, state.ErrNotFound) {
		problem(w, http.StatusNotFound, "not_found", fmt.Sprintf("no %s %q", kind, name))
		return
	}
	if err != nil {
		s.unavailable(w, "read", name, err)
		return
	}
	o.event.Version = sec.Version
	names := make([]string, 0, len(sec.Params))
	for k := range sec.Params {
		names = append(names, k)
	}
	sort.Strings(names)
	params := []shapeParam{}
	for _, k := range names {
		p := shapeParam{Name: k, Type: "VARCHAR",
			Redacted: slices.ContainsFunc(sec.RedactKeys, func(rk string) bool { return strings.EqualFold(rk, k) })}
		raw := sec.Params[k]
		text, isText := paramText(raw)
		if typed, ok := paramType(raw); ok {
			p.Type = typed
		}
		switch {
		case isText && strings.HasPrefix(text, material.Prefix):
			p.Reference = text // a location, written by an administrator: never what it holds
		case values && !p.Redacted:
			p.Value = raw
		}
		params = append(params, p)
	}
	body := map[string]any{"name": sec.Name, "kind": kind, "version": strconv.FormatInt(sec.Version, 10),
		"params": params}
	if kind == "secret" {
		body["type"], body["provider"] = sec.Type, sec.Provider
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(sec.Version, 10)))
	writeJSON(w, http.StatusOK, body)
}

// paramText is a parameter's text: a bare string, or a typed value's string.
func paramText(raw json.RawMessage) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, true
	}
	var typed struct {
		Value json.RawMessage `json:"value"`
	}
	if json.Unmarshal(raw, &typed) == nil && json.Unmarshal(typed.Value, &s) == nil {
		return s, true
	}
	return "", false
}

// paramType is a typed value's DuckDB type; false for a bare string (VARCHAR).
func paramType(raw json.RawMessage) (string, bool) {
	var typed struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &typed) == nil && typed.Type != "" {
		return typed.Type, true
	}
	return "", false
}

// --- a replace that keeps -------------------------------------------------------------------------------

// paramsBody replaces a secret's parameters while keeping those the administrator never saw: every current
// parameter is kept, set or removed - none is dropped by omission.
type paramsBody struct {
	Set        map[string]json.RawMessage `json:"set"`
	Keep       []string                   `json:"keep"`
	Remove     []string                   `json:"remove"`
	RedactKeys []string                   `json:"redact_keys"`
	Comment    *string                    `json:"comment"`
}

func (s *Server) adminParams(w http.ResponseWriter, r *http.Request) {
	var body paramsBody
	if err := readJSON(r, &body); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "the body is {set, keep, remove, redact_keys, comment?}: "+err.Error())
		return
	}
	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	if ifMatch == "" || ifMatch == "*" || strings.HasPrefix(ifMatch, "W/") {
		problem(w, http.StatusPreconditionFailed, "precondition_failed",
			`If-Match is required: the exact version the edit started from ("N", not * nor weak)`)
		return
	}
	now := s.now()
	saved, ok := s.mutate(w, r, "update", func(current *state.Secret) (*state.Secret, error) {
		if strconv.Quote(strconv.FormatInt(current.Version, 10)) != ifMatch {
			return nil, errPrecondition
		}
		params, err := merged(current.Params, body)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errInvalid, err)
		}
		redact := body.RedactKeys
		if redact == nil { // the current marks, of the parameters that remain
			for _, k := range current.RedactKeys {
				if _, ok := params[k]; ok {
					redact = append(redact, k)
				}
			}
		}
		// a kept parameter keeps its mark: unmarking a value the administrator never saw would show it here
		// (shape, values=1) and in every user's duckdb_secrets(); a mark goes only with a value set anew
		marked := func(list []string, k string) bool {
			return slices.ContainsFunc(list, func(rk string) bool { return strings.EqualFold(rk, k) })
		}
		for _, k := range body.Keep {
			if marked(current.RedactKeys, k) && !marked(redact, k) {
				return nil, fmt.Errorf("%w: parameter %q is kept: it stays secret (set a new value to unmark it)", errInvalid, k)
			}
		}
		if err := validParams(params, redact); err != nil {
			return nil, fmt.Errorf("%w: %v", errInvalid, err)
		}
		if current.Provider == tokenExchangeProvider {
			if err := s.validMinted(current.Type, params); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalid, err)
			}
		}
		redact, err = s.material.CheckWrite(current.Provider, params, redact)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errInvalid, err)
		}
		next := *current
		next.Params, next.RedactKeys = params, redact
		if body.Comment != nil {
			next.Comment = *body.Comment
		}
		next.UpdatedAt = now
		next.Version++
		return &next, nil
	})
	if !ok {
		return
	}
	o := observed(r)
	o.event.Version, o.event.Detail = saved.Version, "replaced"
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(saved.Version, 10)))
	writeJSON(w, http.StatusOK, descriptor(saved, s.verbs(callerOf(r), saved)))
}

// merged is current with body applied: kept, set (new or replacing), removed; any current parameter the body
// does not name is an error, as is a name it gives twice or keeps or removes without having it.
func merged(current map[string]json.RawMessage, body paramsBody) (map[string]json.RawMessage, error) {
	said := map[string]string{}
	say := func(k, how string) error {
		if prev, ok := said[k]; ok {
			return fmt.Errorf("parameter %q is both %s and %s", k, prev, how)
		}
		said[k] = how
		return nil
	}
	out := map[string]json.RawMessage{}
	for _, k := range body.Keep {
		if err := say(k, "kept"); err != nil {
			return nil, err
		}
		v, ok := current[k]
		if !ok {
			return nil, fmt.Errorf("parameter %q is kept, but the secret has none", k)
		}
		out[k] = v
	}
	for _, k := range body.Remove {
		if err := say(k, "removed"); err != nil {
			return nil, err
		}
		if _, ok := current[k]; !ok {
			return nil, fmt.Errorf("parameter %q is removed, but the secret has none", k)
		}
	}
	for k, v := range body.Set {
		if err := say(k, "set"); err != nil {
			return nil, err
		}
		out[k] = v
	}
	for k := range current {
		if _, ok := said[k]; !ok {
			return nil, fmt.Errorf("parameter %q is neither kept, set nor removed", k)
		}
	}
	return out, nil
}

// --- grants by principal --------------------------------------------------------------------------------

func (s *Server) adminGrants(w http.ResponseWriter, r *http.Request) {
	principal := r.URL.Query().Get("principal")
	counts := map[string]int{}
	entries := []map[string]any{}
	for _, ns := range []struct {
		kind  string
		store state.Store
	}{{"secret", s.store}, {"variable", s.store.Variables()}} {
		list, err := ns.store.List(r.Context()) // descriptors and grants: no material
		if err != nil {
			s.unavailable(w, "read", "", err)
			return
		}
		for _, sec := range list {
			for _, g := range sec.Grants {
				if !roleOrGroup(g.Principal) || !slices.Contains(g.Verbs, "use") {
					continue // ignored since specs/009
				}
				counts[g.Principal]++
				if g.Principal != principal {
					continue
				}
				others := []string{}
				for _, o := range sec.Grants {
					if o.Principal != principal && roleOrGroup(o.Principal) && !slices.Contains(others, o.Principal) {
						others = append(others, o.Principal)
					}
				}
				entries = append(entries, map[string]any{"kind": ns.kind, "name": sec.Name, "grant_id": g.ID,
					"others": others})
			}
		}
	}
	principals := []map[string]any{}
	names := make([]string, 0, len(counts))
	for p := range counts {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		principals = append(principals, map[string]any{"principal": p, "count": counts[p]})
	}
	body := map[string]any{"principals": principals}
	if principal != "" {
		body["entries"] = entries
	}
	writeJSON(w, http.StatusOK, body)
}

// --- the references check -------------------------------------------------------------------------------

// refsChecks holds one HTTP references check per replica at a time: each reads every entry.
var refsChecks sync.Mutex

func (s *Server) adminRefsCheck(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Resolve bool `json:"resolve"`
	}
	if err := readJSON(r, &body); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "the body is {\"resolve\": true | false}")
		return
	}
	if !refsChecks.TryLock() {
		problem(w, http.StatusServiceUnavailable, "service_unavailable", "a references check is running: try again when it ends")
		return
	}
	defer refsChecks.Unlock()
	// with reads it may outlast the server's write timeout
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(refsCheckTime + time.Minute)); err != nil {
		s.log.Warn("the references check keeps the server's write timeout", "error", err.Error())
	}
	ctx, cancel := context.WithTimeout(r.Context(), refsCheckTime)
	defer cancel()
	findings := []refscheck.Finding{}
	checked, err := refscheck.Run(ctx, s.store, s.material, body.Resolve, func(f refscheck.Finding) {
		findings = append(findings, f)
	})
	if err != nil {
		s.log.Error("the references check stopped", "error", err.Error())
		problem(w, http.StatusServiceUnavailable, "service_unavailable", "the references check stopped: the store or the KEK did not answer")
		return
	}
	observed(r).event.Detail = fmt.Sprintf("checked %d, %d findings", checked, len(findings))
	writeJSON(w, http.StatusOK, map[string]any{"checked": checked, "resolve": body.Resolve, "findings": findings})
}
