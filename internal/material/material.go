// Package material is material by reference (spec 002): a parameter's value `ref+<scheme>://...` names where
// the value lives - Azure Key Vault first - and the service reads it at each fetch, with its own identity,
// within an allowlist. A reference is checked when it is written and again when it is resolved; one that does
// not resolve is an error for that fetch, never an empty or a stale value. Nothing here logs a value.
package material

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Prefix marks a parameter's value as a reference.
const Prefix = "ref+"

// Ref is a parsed reference.
type Ref struct {
	Scheme string // "azkv", "k8s"
	// Where, as the source parsed it: for Key Vault the vault, the secret, a version or ""; for Kubernetes the
	// namespace (Vault), the Secret (Name) and its key (Key).
	Vault, Name, Key, Version string
}

// String is the reference as logged: where, never a value.
func (r Ref) String() string {
	if r.Scheme == "vault" { // <mount>/<path>#<field>: a path has slashes of its own
		return Prefix + "vault://" + r.Vault + "/" + r.Name + "#" + r.Key
	}
	s := Prefix + r.Scheme + "://" + r.Vault + "/" + r.Name
	for _, part := range []string{r.Key, r.Version} {
		if part != "" {
			s += "/" + part
		}
	}
	return s
}

// Source reads what references of one scheme name.
type Source interface {
	Scheme() string
	// Parse checks a reference's text (after the scheme) and the allowlist; an error says what is wrong
	// with it, never a value.
	Parse(text string) (Ref, error)
	// Resolve reads the value, with the service's identity, after checking the allowlist again; it names
	// the version read.
	Resolve(ctx context.Context, ref Ref) (value string, version string, err error)
}

// Resolver holds the configured sources. A nil Resolver knows no scheme: every reference is refused.
type Resolver struct {
	sources map[string]Source
}

// New returns a resolver over sources.
func New(sources ...Source) *Resolver {
	r := &Resolver{sources: map[string]Source{}}
	for _, s := range sources {
		r.sources[s.Scheme()] = s
	}
	return r
}

var (
	// ErrInvalid: a reference that may not be written (422).
	ErrInvalid = errors.New("invalid reference")
	// ErrUnresolved: a reference that did not resolve at a fetch (503).
	ErrUnresolved = errors.New("a reference did not resolve")
)

// param is one parameter's value as the protocol has it: a text, or {type, value}.
type param struct {
	typed bool
	typ   string
	text  string
	isStr bool
}

func readParam(raw json.RawMessage) param {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return param{text: s, isStr: true, typ: "VARCHAR"}
	}
	// exactly the keys type and value, as written (the API refuses any other shape)
	var typed map[string]json.RawMessage
	if json.Unmarshal(raw, &typed) != nil || len(typed) != 2 || typed["type"] == nil || typed["value"] == nil {
		return param{}
	}
	p := param{typed: true}
	if json.Unmarshal(typed["type"], &p.typ) != nil {
		return param{}
	}
	if json.Unmarshal(typed["value"], &p.text) == nil {
		p.isStr = true
	}
	return p
}

var schemeName = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// parse splits a reference's text: its scheme and the rest. The text is named in no error: a scheme that is
// not one may be a value written by mistake.
func (r *Resolver) parse(text string) (Source, Ref, error) {
	rest := strings.TrimPrefix(text, Prefix)
	scheme, where, ok := strings.Cut(rest, "://")
	if !ok || !schemeName.MatchString(scheme) {
		return nil, Ref{}, fmt.Errorf("%w: ref+<scheme>://..., the scheme in lower-case letters and digits", ErrInvalid)
	}
	var src Source
	if r != nil {
		src = r.sources[scheme]
	}
	if src == nil {
		return nil, Ref{}, fmt.Errorf("%w: no source for %s references is configured (material:)", ErrInvalid, scheme)
	}
	ref, err := src.Parse(where)
	if err != nil {
		return nil, Ref{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return src, ref, nil
}

// CheckWrite checks a secret's params at a write: every value that starts with ref+ is a reference to a
// configured source, well formed and within its allowlist - never stored as a literal - and only in a
// VARCHAR value, never in a secret minted per caller. It returns the redact keys, with every reference's
// parameter in them: a resolved value must never show in duckdb_secrets().
func (r *Resolver) CheckWrite(provider string, params map[string]json.RawMessage, redact []string) ([]string, error) {
	out := slices.Clone(redact)
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, key := range keys {
		p := readParam(params[key])
		if !p.isStr {
			continue
		}
		if !strings.HasPrefix(p.text, Prefix) {
			// a near miss (REF+, a space before it) would be kept as text: an administrator's typo said, not stored
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(p.text)), Prefix) {
				return nil, fmt.Errorf("%w: parameter %s: a reference is written exactly ref+<scheme>://...", ErrInvalid, key)
			}
			continue
		}
		if !strings.EqualFold(p.typ, "VARCHAR") {
			return nil, fmt.Errorf("%w: parameter %s is a %s: a reference is a VARCHAR value", ErrInvalid, key, p.typ)
		}
		if provider == "token_exchange" {
			return nil, fmt.Errorf("%w: a token_exchange secret holds no reference (parameter %s)", ErrInvalid, key)
		}
		if _, _, err := r.parse(p.text); err != nil {
			return nil, fmt.Errorf("parameter %s: %w", key, err)
		}
		if !slices.Contains(out, key) {
			out = append(out, key)
		}
	}
	return out, nil
}

// Resolution is one reference read at a fetch, as logged: where and which version, never the value.
type Resolution struct {
	Param   string
	Ref     Ref
	Version string
}

// Resolve returns params with every reference replaced by the value it names, read now; any reference that
// does not resolve fails the whole fetch (ErrUnresolved) - never an empty or a stale value.
func (r *Resolver) Resolve(ctx context.Context, params map[string]json.RawMessage) (map[string]json.RawMessage, []Resolution, error) {
	var out map[string]json.RawMessage
	var done []Resolution
	for key, raw := range params {
		p := readParam(raw)
		if !p.isStr || !strings.HasPrefix(p.text, Prefix) {
			continue
		}
		src, ref, err := r.parse(p.text) // the allowlist again: the configuration may have changed
		if err != nil {
			// ErrInvalid too: it will not resolve until the configuration changes
			return nil, nil, fmt.Errorf("%w: parameter %s: %w", ErrUnresolved, key, err)
		}
		value, version, err := src.Resolve(ctx, ref)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: parameter %s (%s): %v", ErrUnresolved, key, ref, err)
		}
		var resolved []byte
		if p.typed {
			resolved, err = json.Marshal(map[string]any{"type": p.typ, "value": value})
		} else {
			resolved, err = json.Marshal(value)
		}
		if err != nil {
			return nil, nil, err
		}
		if out == nil {
			out = make(map[string]json.RawMessage, len(params))
			for k, v := range params {
				out[k] = v
			}
		}
		out[key] = resolved
		done = append(done, Resolution{Param: key, Ref: ref, Version: version})
	}
	if out == nil {
		return params, nil, nil
	}
	return out, done, nil
}

// Admits says whether a reference's text parses and is within a configured allowlist: what an administrator
// could write.
func (r *Resolver) Admits(text string) bool {
	_, _, err := r.parse(text)
	return err == nil
}

// ResolveOne reads what one reference names (state.password_ref): within its source's allowlist, never logged.
func (r *Resolver) ResolveOne(ctx context.Context, text string) (string, error) {
	src, ref, err := r.parse(text)
	if err != nil {
		return "", err
	}
	value, _, err := src.Resolve(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %v", ErrUnresolved, ref, err)
	}
	return value, nil
}
