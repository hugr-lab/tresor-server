package api

// Generated parameters (spec 023; tresor spec 029): a VARCHAR value - a parameter's whole string, or a string
// inside a typed value (VARCHAR, MAP, STRUCT, LIST) - is made on each read for the effective user: the direct
// caller, or under a delegation grant the grant's user, never the server.
//   - the whole value `mint+<kind>://…` (the syntax tresor's reference server shares);
//   - a part of a string `${<kind>://…}` (this service only);
//   - kinds: exchange://<audience>[?scope=<scope>] (a token for the user, RFC 8693 or OBO), claim://<claim> (a
//     top-level claim of the user's verified token, never the token);
//   - literals: `mint++x` is served as `mint+x` (one `+` dropped), `$${` as `${`.
//
// The secret is then dynamic; every key holding a generated value is added to redact_keys; expires_at is the
// earliest expiry of what was made, less a margin. `provider: token_exchange` (specs/010) stays an alias: an
// exchange of the type's token parameter, served with the consumer's provider, config. Nothing generated is
// logged or put in an error: the errors name the parameter, never its value.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hugr-lab/tresor-server/internal/auth"
	"github.com/hugr-lab/tresor-server/internal/state"
)

const (
	generatorPrefix = "mint+"
	defaultMargin   = 10 * time.Minute // expires_at this long before what was made expires (spec 023)
)

// servedProvider is the descriptor's provider: the stored one, the consumer's - the token_exchange alias's is
// config (the protocol never serves a name for the service's mechanism).
func servedProvider(sec *state.Secret) string {
	if sec.Provider == tokenExchangeProvider {
		return "config"
	}
	return sec.Provider
}

// isDynamic: the descriptor's dynamic - the row's marker (spec 023), or the token_exchange alias.
func isDynamic(sec *state.Secret) bool { return sec.Dynamic || isMinted(sec) }

// generator is one value made on each read.
type generator struct {
	kind     string // "exchange" | "claim"
	audience string // exchange
	scope    string // exchange, optional
	claim    string // claim
}

// key identifies what a generator makes, so a read makes it once.
func (g *generator) key() string {
	return g.kind + "\x00" + g.audience + "\x00" + g.scope + "\x00" + g.claim
}

// parseGenerator reads `<kind>://<body>`. The error names no value: an administrator's value may be a secret.
func parseGenerator(kind, body string) (*generator, error) {
	switch kind {
	case "exchange":
		rawAudience, query, _ := strings.Cut(body, "?")
		audience, err := url.PathUnescape(rawAudience)
		if err != nil || audience == "" {
			return nil, errors.New("is an exchange:// generator with no audience")
		}
		values, err := url.ParseQuery(query)
		if err != nil {
			return nil, errors.New("is an exchange:// generator with a malformed query")
		}
		for key, v := range values {
			if key != "scope" || len(v) != 1 {
				return nil, errors.New("is an exchange:// generator: its query is ?scope=<scope> only")
			}
		}
		return &generator{kind: kind, audience: audience, scope: values.Get("scope")}, nil
	case "claim":
		if body == "" {
			return nil, errors.New("is a claim:// generator with no claim name")
		}
		if auth.BindingClaims[body] {
			return nil, errors.New("is a claim:// generator of a session claim, never served")
		}
		return &generator{kind: kind, claim: body}, nil
	case "login", "rule":
		return nil, fmt.Errorf("is a %s:// generator, not available in this version", kind)
	}
	return nil, errors.New("is a generator of an unknown kind (exchange://, claim://)")
}

// generatorKinds are the kinds a `${…}` names; any other `${` is a literal.
var generatorKinds = []string{"exchange", "claim", "login", "rule"}

// piece is a part of a string value: a literal, or a generator.
type piece struct {
	literal string
	gen     *generator
}

// parseString reads a stored string: its pieces, and whether it holds a generator or an escape (a string that
// holds neither is served as it is).
func parseString(value string) ([]piece, bool, error) {
	if rest, ok := strings.CutPrefix(value, generatorPrefix); ok {
		if lit, escaped := strings.CutPrefix(rest, "+"); escaped { // the escape: one `+` dropped
			return []piece{{literal: generatorPrefix + lit}}, true, nil
		}
		kind, body, ok := strings.Cut(rest, "://")
		if !ok {
			return nil, false, errors.New("begins with mint+ but is no mint+<kind>://… generator (a literal is written mint++…)")
		}
		gen, err := parseGenerator(kind, body)
		if err != nil {
			return nil, false, err
		}
		return []piece{{gen: gen}}, true, nil
	}
	if !strings.Contains(value, "${") {
		return nil, false, nil
	}
	var pieces []piece
	var lit strings.Builder
	special := false
	for i := 0; i < len(value); {
		if strings.HasPrefix(value[i:], "$${") { // a literal ${
			lit.WriteString("${")
			i += 3
			special = true
			continue
		}
		if strings.HasPrefix(value[i:], "${") {
			if kind, ok := namedKind(value[i+2:]); ok {
				end := strings.IndexByte(value[i:], '}')
				if end < 0 {
					return nil, false, fmt.Errorf("has a ${%s://… with no closing }", kind)
				}
				gen, err := parseGenerator(kind, value[i+2+len(kind)+3:i+end])
				if err != nil {
					return nil, false, err
				}
				if lit.Len() > 0 {
					pieces = append(pieces, piece{literal: lit.String()})
					lit.Reset()
				}
				pieces = append(pieces, piece{gen: gen})
				i += end + 1
				special = true
				continue
			}
		}
		lit.WriteByte(value[i])
		i++
	}
	if lit.Len() > 0 {
		pieces = append(pieces, piece{literal: lit.String()})
	}
	return pieces, special, nil
}

// namedKind: the text after `${` names a generator's kind (`<kind>://`).
func namedKind(rest string) (string, bool) {
	for _, kind := range generatorKinds {
		if strings.HasPrefix(rest, kind+"://") {
			return kind, true
		}
	}
	return "", false
}

// walkStrings calls fn on every string of a parameter's value - the value itself when it is a string, the
// value of a typed one ({type, value}: a VARCHAR, or the strings inside a MAP, STRUCT or LIST; never a key) -
// and returns the value with fn's results, unchanged where fn changed nothing.
func walkStrings(raw json.RawMessage, fn func(string) (string, bool, error)) (json.RawMessage, bool, error) {
	var str string
	if json.Unmarshal(raw, &str) == nil {
		out, changed, err := fn(str)
		if err != nil || !changed {
			return raw, false, err
		}
		b, err := json.Marshal(out)
		return b, true, err
	}
	var typed map[string]json.RawMessage
	if json.Unmarshal(raw, &typed) != nil || typed["value"] == nil {
		return raw, false, nil // checked at PUT: never here
	}
	var typ string
	if json.Unmarshal(typed["type"], &typ) != nil || !textual(typ) {
		return raw, false, nil // a BLOB, a number, a date: never read for generators
	}
	dec := json.NewDecoder(bytes.NewReader(typed["value"]))
	dec.UseNumber() // every digit kept
	var value any
	if err := dec.Decode(&value); err != nil {
		return raw, false, nil
	}
	walked, changed, err := walkAny(value, fn)
	if err != nil || !changed {
		return raw, false, err
	}
	typed["value"], err = json.Marshal(walked)
	if err != nil {
		return raw, false, err
	}
	b, err := json.Marshal(typed)
	return b, true, err
}

// textual: a type whose strings are text - VARCHAR, and the strings inside a MAP, STRUCT or LIST.
func textual(typ string) bool {
	t := strings.ToUpper(strings.TrimSpace(typ))
	return t == "VARCHAR" || strings.HasPrefix(t, "MAP(") || strings.HasPrefix(t, "STRUCT(") ||
		strings.HasPrefix(t, "LIST(") || strings.HasSuffix(t, "[]")
}

func walkAny(v any, fn func(string) (string, bool, error)) (any, bool, error) {
	switch t := v.(type) {
	case string:
		out, changed, err := fn(t)
		return out, changed, err
	case []any:
		changed := false
		for i, item := range t {
			out, c, err := walkAny(item, fn)
			if err != nil {
				return v, false, err
			}
			t[i], changed = out, changed || c
		}
		return t, changed, nil
	case map[string]any:
		changed := false
		for k, item := range t {
			out, c, err := walkAny(item, fn)
			if err != nil {
				return v, false, err
			}
			t[k], changed = out, changed || c
		}
		return t, changed, nil
	}
	return v, false, nil
}

// generatorsOf are a secret's generated parameters, by key (each with its generators), and the token_exchange
// alias's. refs are the parameters that are references (ref+…): never read for generators.
func generatorsOf(typ, provider string, params map[string]json.RawMessage, refs map[string]bool) (map[string][]*generator, error) {
	gens := map[string][]*generator{}
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys) // the same error for the same secret
	for _, key := range keys {
		if refs[key] {
			continue
		}
		_, _, err := walkStrings(params[key], func(s string) (string, bool, error) {
			pieces, _, err := parseString(s)
			for _, p := range pieces {
				if p.gen != nil {
					gens[key] = append(gens[key], p.gen)
				}
			}
			return s, false, err
		})
		if err != nil {
			return nil, fmt.Errorf("parameter %q %v", key, err)
		}
	}
	if provider == tokenExchangeProvider {
		if param, ok := tokenParam[strings.ToLower(typ)]; ok {
			audience, scope := mintTarget(params)
			gens[param] = []*generator{{kind: "exchange", audience: audience, scope: scope}}
		}
	}
	return gens, nil
}

// checkGenerators checks a secret's generators at a write: well formed, of a kind this version makes, and no
// exchange for this service's own audience (a user's token for this service, in a secret sent to another
// server, could be replayed here). It says whether the secret is dynamic.
func (s *Server) checkGenerators(typ, provider string, params map[string]json.RawMessage) (bool, error) {
	gens, err := generatorsOf(typ, provider, params, s.material.Refs(params))
	if err != nil {
		return false, err
	}
	for key, list := range gens {
		for _, gen := range list {
			if gen.kind != "exchange" {
				continue
			}
			for _, is := range s.cfg.Issuers {
				if gen.audience == is.Audience {
					return false, fmt.Errorf("parameter %q exchanges for this service's own audience, never allowed", key)
				}
			}
		}
	}
	return len(gens) > 0, nil
}

// made is one generated value and when it expires (zero: never named).
type made struct {
	value  string
	expiry time.Time
}

// generated replaces, in params (references resolved already), every generated value with one made for the
// effective user, and unescapes literals; it reads the stored values (sec.Params), never what a reference read
// (refs: those keys are left as resolved). It returns the keys that hold a generated value and the earliest
// expiry. A row not marked dynamic - written before 0.5 - makes nothing: a string holding a generator is served
// as stored, so a secret said static is never one made per caller.
func (s *Server) generated(r *http.Request, c *auth.Caller, sec *state.Secret, params map[string]json.RawMessage,
	refs map[string]bool) ([]string, time.Time, *mintProblem) {
	cache := map[string]made{}
	var expires time.Time
	var problem *mintProblem
	make1 := func(gen *generator) (string, error) {
		if m, ok := cache[gen.key()]; ok {
			return m.value, nil
		}
		value, expiry, p := s.generate(r, c, gen)
		if p != nil {
			problem = p
			return "", errors.New("refused")
		}
		if value == "" { // never an empty value in place of what could not be made
			problem = refusedMint("a value was generated empty")
			return "", errors.New("refused")
		}
		cache[gen.key()] = made{value, expiry}
		if !expiry.IsZero() && (expires.IsZero() || expiry.Before(expires)) {
			expires = expiry
		}
		return value, nil
	}
	var keys []string
	names := make([]string, 0, len(sec.Params))
	for key := range sec.Params {
		names = append(names, key)
	}
	sort.Strings(names)
	for _, key := range names {
		if refs[key] {
			continue
		}
		hasGen := false
		out, changed, err := walkStrings(sec.Params[key], func(str string) (string, bool, error) {
			pieces, special, err := parseString(str)
			if err != nil && !sec.Dynamic {
				return str, false, nil // written before 0.5, unchecked: a literal
			}
			if err != nil || !special {
				return str, false, err
			}
			if !sec.Dynamic && slices.ContainsFunc(pieces, func(p piece) bool { return p.gen != nil }) {
				return str, false, nil // written before 0.5: a literal
			}
			var b strings.Builder
			for _, p := range pieces {
				if p.gen == nil {
					b.WriteString(p.literal)
					continue
				}
				hasGen = true
				value, err := make1(p.gen)
				if err != nil {
					return str, false, err
				}
				b.WriteString(value)
			}
			return b.String(), true, nil
		})
		if problem != nil {
			return nil, time.Time{}, problem
		}
		if err != nil { // stored before generators were checked: never served as it is
			return nil, time.Time{}, &mintProblem{http.StatusInternalServerError, "service_error",
				"the secret cannot be served: parameter " + strconv.Quote(key) + " " + err.Error()}
		}
		if changed {
			params[key] = out
		}
		if hasGen {
			keys = append(keys, key)
		}
	}
	if sec.Provider == tokenExchangeProvider {
		if param, ok := tokenParam[strings.ToLower(sec.Type)]; ok {
			audience, scope := mintTarget(sec.Params)
			value, err := make1(&generator{kind: "exchange", audience: audience, scope: scope})
			if err != nil {
				return nil, time.Time{}, problem
			}
			params[param], _ = json.Marshal(value)
			keys = append(keys, param)
		}
	}
	return keys, expires, nil
}

// generate makes one value for the effective user.
func (s *Server) generate(r *http.Request, c *auth.Caller, gen *generator) (string, time.Time, *mintProblem) {
	switch gen.kind {
	case "exchange":
		token, problem := s.mintedToken(r, c, gen.audience, gen.scope)
		if problem != nil {
			return "", time.Time{}, problem
		}
		if token.Expiry.IsZero() { // the IdP named none: a client still caches it for a bounded time
			return token.Access, s.now().Add(mintNoExpiry), nil
		}
		return token.Access, token.Expiry, nil
	case "claim":
		value, ok := c.Claims[gen.claim]
		if !ok || value == "" {
			if c.Actor != "" {
				// a grant keeps the claims its secrets named at its exchange
				return "", time.Time{}, refusedMint("the delegation grant holds no claim " + strconv.Quote(gen.claim) +
					" (the user's token had none, or the secret was granted since): a new session carries it")
			}
			return "", time.Time{}, refusedMint("the caller's token carries no text claim " + strconv.Quote(gen.claim))
		}
		if strings.Count(value, ".") == 2 && !strings.ContainsAny(value, " @") {
			// shaped like a JWT: a claim carrying a token is never served
			return "", time.Time{}, refusedMint("the claim " + strconv.Quote(gen.claim) + " holds a token, never served")
		}
		// as long as the token it came from (under a grant: the grant)
		if c.ExpiresAt.IsZero() {
			return value, s.now().Add(mintNoExpiry), nil
		}
		return value, c.ExpiresAt, nil
	}
	return "", time.Time{}, refusedMint("a generator of an unknown kind")
}

// expiresAt is what a client is told: the earliest expiry less the margin - at most half of what is left, so
// a short-lived value is still served for a while.
func (s *Server) expiresAt(expiry time.Time) time.Time {
	margin := s.cfg.Dynamic.Margin
	if margin == 0 {
		margin = defaultMargin
	}
	if left := expiry.Sub(s.now()); margin > left/2 {
		margin = max(left/2, 0)
	}
	return expiry.Add(-margin)
}

// withKeys is redact plus keys, each once.
func withKeys(redact, keys []string) []string {
	out := slices.Clone(redact)
	if out == nil {
		out = []string{}
	}
	for _, k := range keys {
		if !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	return out
}
