// Package vaultkv resolves `ref+vault://<mount>/<path>#<field>` (spec 007): one field of a KV v2 secret in
// OpenBao or HashiCorp Vault, read with the service's Vault login, within an allowlist of mounts and path
// prefixes. The URL is built from the parsed parts, never from the text.
package vaultkv

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/hugr-lab/tresor-server/internal/material"
	"github.com/hugr-lab/tresor-server/internal/vault"
)

// Caller is the Vault client: vault.Client, or a fake in tests.
type Caller interface {
	Do(ctx context.Context, method, path string, body, out any) error
}

// Allow lets references read one mount's secrets whose paths start with one of the prefixes (all, when none).
type Allow struct {
	Mount    string
	Prefixes []string
}

// Source resolves vault references.
type Source struct {
	name     string // the scheme: "vault", or a named source's (spec 008)
	vault    Caller
	allow    []Allow
	cacheTTL time.Duration

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	value, version string
	until          time.Time
}

// New returns a source over the allowlist; cacheTTL keeps a value read that long (0: read at every fetch).
func New(v Caller, allow []Allow, cacheTTL time.Duration) *Source {
	return &Source{name: "vault", vault: v, allow: allow, cacheTTL: cacheTTL, cache: map[string]cached{}}
}

// Named is the source under another name (spec 008): ref+<name>://.
func (s *Source) Named(name string) *Source {
	s.name = name
	return s
}

func (s *Source) Scheme() string { return s.name }
func (s *Source) Kind() string   { return "vault" }

// allowlist names the setting that lists what this source may read.
func (s *Source) allowlist() string {
	if s.name == "vault" {
		return "material.vault.allow"
	}
	return "material.sources[" + s.name + "].allow"
}

var (
	segment = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$`)
	field   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
)

// Parse checks <mount>/<path>#<field>: a one-segment mount, a path of KV's characters (no . nor .. segment, no
// escape, no query), a field - and the allowlist.
func (s *Source) Parse(text string) (material.Ref, error) {
	where, fld, ok := strings.Cut(text, "#")
	if !ok || !field.MatchString(fld) {
		return material.Ref{}, fmt.Errorf("ref+%s://<mount>/<path>#<field>", s.name)
	}
	mount, path, ok := strings.Cut(where, "/")
	if !ok || !segment.MatchString(mount) || mount == ".." || path == "" {
		return material.Ref{}, fmt.Errorf("ref+%s://<mount>/<path>#<field>: a mount, then a path", s.name)
	}
	for _, seg := range strings.Split(path, "/") {
		if !segment.MatchString(seg) || seg == ".." {
			return material.Ref{}, errors.New("a vault path's segments are letters, digits, _ . - (no . nor ..)")
		}
	}
	ref := material.Ref{Scheme: s.name, Kind: "vault", Vault: mount, Name: path, Key: fld}
	if !s.allowed(ref) {
		return material.Ref{}, fmt.Errorf("%s is outside the allowlist (%s)", ref, s.allowlist())
	}
	return ref, nil
}

func (s *Source) allowed(ref material.Ref) bool {
	for _, a := range s.allow {
		if a.Mount != ref.Vault {
			continue
		}
		if len(a.Prefixes) == 0 {
			return true
		}
		for _, p := range a.Prefixes {
			if strings.HasPrefix(ref.Name, p) {
				return true
			}
		}
	}
	return false
}

// Resolve reads the field now (or from the cache); the version is the KV secret's.
func (s *Source) Resolve(ctx context.Context, ref material.Ref) (string, string, error) {
	if !s.allowed(ref) { // the allowlist again: a reference is never resolved outside it
		return "", "", fmt.Errorf("%s is outside the allowlist", ref)
	}
	key := ref.String()
	s.mu.Lock()
	if c, ok := s.cache[key]; ok && time.Now().Before(c.until) {
		s.mu.Unlock()
		return c.value, c.version, nil
	}
	s.mu.Unlock()
	var out struct {
		Data struct {
			Data     map[string]any `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := s.vault.Do(ctx, http.MethodGet, ref.Vault+"/data/"+ref.Name, nil, &out); err != nil {
		var ve *vault.Error
		if errors.As(err, &ve) && ve.Status == http.StatusNotFound {
			return "", "", errors.New("no such KV secret (missing, deleted or destroyed)")
		}
		return "", "", err // the client's error: a status and Vault's words, never a value
	}
	if out.Data.Metadata.Version < 1 {
		return "", "", errors.New("not a KV v2 secret: the mount is not KV version 2")
	}
	raw, ok := out.Data.Data[ref.Key]
	if !ok {
		return "", "", errors.New("the KV secret has no such field")
	}
	value, ok := raw.(string)
	if !ok || !utf8.ValidString(value) {
		return "", "", errors.New("the KV secret's field is not text: a reference is a VARCHAR value")
	}
	version := strconv.Itoa(out.Data.Metadata.Version)
	if s.cacheTTL > 0 {
		s.mu.Lock()
		s.cache[key] = cached{value: value, version: version, until: time.Now().Add(s.cacheTTL)}
		s.mu.Unlock()
	}
	return value, version, nil
}
