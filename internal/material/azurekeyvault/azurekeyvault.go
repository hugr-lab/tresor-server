// Package azurekeyvault resolves `ref+azkv://<vault>/<secret>[/<version>]` (spec 002): a Key Vault secret,
// read with the service's identity (Key Vault Secrets User), within an allowlist of vaults and secret-name
// prefixes. The URL to the vault is built from the parsed parts, never from the text.
package azurekeyvault

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/hugr-lab/tresor-server/internal/material"
)

// Allow lets references read one vault's secrets whose names start with one of the prefixes (all, when none).
type Allow struct {
	Vault    string
	Prefixes []string
}

// Getter reads a secret: azsecrets.Client, or a fake in tests.
type Getter interface {
	GetSecret(ctx context.Context, name, version string, opts *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
}

// Source resolves azkv references.
type Source struct {
	allow     []Allow
	suffix    string // .vault.azure.net, or a sovereign cloud's
	cacheTTL  time.Duration
	newGetter func(vaultURL string) (Getter, error)

	mu      sync.Mutex
	getters map[string]Getter
	cache   map[string]cached
}

type cached struct {
	value, version string
	until          time.Time
}

// Options configure a source; zero values take the defaults.
type Options struct {
	DNSSuffix string        // default .vault.azure.net
	CacheTTL  time.Duration // default 0: read at every fetch
}

// New returns a source over the allowlist, reading with cred.
func New(allow []Allow, cred azcore.TokenCredential, opts Options) *Source {
	return NewWithGetter(allow, func(vaultURL string) (Getter, error) {
		return azsecrets.NewClient(vaultURL, cred, nil)
	}, opts)
}

// NewWithGetter is New over given getters (tests).
func NewWithGetter(allow []Allow, newGetter func(vaultURL string) (Getter, error), opts Options) *Source {
	if opts.DNSSuffix == "" {
		opts.DNSSuffix = ".vault.azure.net"
	}
	return &Source{allow: allow, suffix: opts.DNSSuffix, cacheTTL: opts.CacheTTL, newGetter: newGetter,
		getters: map[string]Getter{}, cache: map[string]cached{}}
}

func (s *Source) Scheme() string { return "azkv" }

var (
	vaultName   = regexp.MustCompile(`^[0-9A-Za-z-]{3,24}$`)
	secretName  = regexp.MustCompile(`^[0-9A-Za-z-]{1,127}$`)
	versionName = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
)

// Parse checks <vault>/<secret>[/<version>]: strict names, no escape, no other segment, no query - and the
// allowlist. Key Vault names are case-insensitive: they are compared so.
func (s *Source) Parse(text string) (material.Ref, error) {
	parts := strings.Split(text, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return material.Ref{}, errors.New("ref+azkv://<vault>/<secret>[/<version>]")
	}
	ref := material.Ref{Scheme: "azkv", Vault: strings.ToLower(parts[0]), Name: parts[1]}
	if len(parts) == 3 {
		ref.Version = strings.ToLower(parts[2])
	}
	switch {
	case !vaultName.MatchString(ref.Vault):
		return material.Ref{}, errors.New("a vault's name is 3 to 24 letters, digits or dashes")
	case !secretName.MatchString(ref.Name):
		return material.Ref{}, errors.New("a Key Vault secret's name is 1 to 127 letters, digits or dashes")
	case len(parts) == 3 && !versionName.MatchString(ref.Version):
		return material.Ref{}, errors.New("a Key Vault secret's version is 32 hex digits")
	case !s.allowed(ref):
		return material.Ref{}, fmt.Errorf("%s is outside the allowlist (material.azkv.allow)", ref)
	}
	return ref, nil
}

func (s *Source) allowed(ref material.Ref) bool {
	for _, a := range s.allow {
		if !strings.EqualFold(a.Vault, ref.Vault) {
			continue
		}
		if len(a.Prefixes) == 0 {
			return true
		}
		for _, p := range a.Prefixes {
			if strings.HasPrefix(strings.ToLower(ref.Name), strings.ToLower(p)) {
				return true
			}
		}
	}
	return false
}

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
	getter := s.getters[ref.Vault]
	s.mu.Unlock()
	if getter == nil {
		g, err := s.newGetter("https://" + ref.Vault + s.suffix)
		if err != nil {
			return "", "", err
		}
		s.mu.Lock()
		s.getters[ref.Vault], getter = g, g
		s.mu.Unlock()
	}
	resp, err := getter.GetSecret(ctx, ref.Name, ref.Version, nil)
	if err != nil {
		return "", "", describe(err)
	}
	if resp.Attributes != nil && resp.Attributes.Enabled != nil && !*resp.Attributes.Enabled {
		return "", "", errors.New("the Key Vault secret is disabled")
	}
	if resp.Value == nil {
		return "", "", errors.New("the Key Vault secret has no value")
	}
	version := ref.Version
	if resp.ID != nil {
		version = resp.ID.Version()
	}
	if s.cacheTTL > 0 {
		s.mu.Lock()
		s.cache[key] = cached{value: *resp.Value, version: version, until: time.Now().Add(s.cacheTTL)}
		s.mu.Unlock()
	}
	return *resp.Value, version, nil
}

// describe is a vault or credential error: its status and code, never a body.
func describe(err error) error {
	var re *azcore.ResponseError
	if errors.As(err, &re) {
		return fmt.Errorf("the vault answered %d %s", re.StatusCode, re.ErrorCode)
	}
	var auth *azidentity.AuthenticationFailedError
	if errors.As(err, &auth) {
		return errors.New("the service's Azure credential did not get a token (azure.identity)")
	}
	return err
}
