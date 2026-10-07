// Package gcpsm resolves `ref+gcp://<project>/<secret>[/<version>]` (spec 012): a GCP Secret Manager secret's
// version (the latest by default), read with the service's GCP identity, within an allowlist of projects and
// secret-name prefixes. The request is built from the parsed parts, never from the text; the payload is checked
// by its CRC32C.
package gcpsm

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hugr-lab/tresor-server/internal/material"
)

// Accessor reads a secret's version: secretmanager.Client, or a fake in tests.
type Accessor interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
}

// Allow lets references read one project's secrets whose names start with one of the prefixes (all, when none).
type Allow struct {
	Project  string
	Prefixes []string
}

// Source resolves gcp references.
type Source struct {
	name     string // the scheme: "gcp", or a named source's (spec 008)
	sm       Accessor
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
func New(sm Accessor, allow []Allow, cacheTTL time.Duration) *Source {
	return &Source{name: "gcp", sm: sm, allow: allow, cacheTTL: cacheTTL, cache: map[string]cached{}}
}

// Named is the source under another name (spec 008): ref+<name>://.
func (s *Source) Named(name string) *Source {
	s.name = name
	return s
}

func (s *Source) Scheme() string { return s.name }
func (s *Source) Kind() string   { return "gcp" }

func (s *Source) allowlist() string {
	if s.name == "gcp" {
		return "material.gcp.allow"
	}
	return "material.sources[" + s.name + "].allow"
}

var (
	// a project's id, or its number
	projectID  = regexp.MustCompile(`^([a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20})$`)
	secretID   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
	versionNum = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
)

// ProjectID reports whether s is a project's id or number (configuration).
func ProjectID(s string) bool { return projectID.MatchString(s) }

// Parse checks <project>/<secret>[/<version>] and the allowlist; a version is a number (the latest when none).
func (s *Source) Parse(text string) (material.Ref, error) {
	parts := strings.Split(text, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return material.Ref{}, fmt.Errorf("ref+%s://<project>/<secret>[/<version>]", s.name)
	}
	ref := material.Ref{Scheme: s.name, Kind: "gcp", Vault: parts[0], Name: parts[1]}
	if len(parts) == 3 {
		ref.Version = parts[2]
	}
	switch {
	case !projectID.MatchString(ref.Vault):
		return material.Ref{}, errors.New("a GCP project is its id (6 to 30 lower-case letters, digits or dashes) or its number")
	case !secretID.MatchString(ref.Name):
		return material.Ref{}, errors.New("a Secret Manager secret's name is 1 to 255 letters, digits, _ or -")
	case len(parts) == 3 && !versionNum.MatchString(ref.Version):
		return material.Ref{}, errors.New("a Secret Manager version is its number (none: the latest)")
	case !s.allowed(ref):
		return material.Ref{}, fmt.Errorf("%s is outside the allowlist (%s)", ref, s.allowlist())
	}
	return ref, nil
}

func (s *Source) allowed(ref material.Ref) bool {
	for _, a := range s.allow {
		if a.Project != ref.Vault {
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

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

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
	version := ref.Version
	if version == "" {
		version = "latest"
	}
	out, err := s.sm.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: "projects/" + ref.Vault + "/secrets/" + ref.Name + "/versions/" + version})
	if err != nil {
		return "", "", describe(err)
	}
	data := out.GetPayload().GetData()
	if c := out.GetPayload().GetDataCrc32C(); c == 0 || c != int64(crc32.Checksum(data, castagnoli)) {
		return "", "", errors.New("the Secret Manager payload failed its CRC32C check")
	}
	if !utf8.Valid(data) {
		return "", "", errors.New("the Secret Manager secret is not UTF-8 text: a reference is a text value")
	}
	value := string(data)
	read := out.GetName()[strings.LastIndex(out.GetName(), "/")+1:]
	if s.cacheTTL > 0 {
		s.mu.Lock()
		s.cache[key] = cached{value: value, version: read, until: time.Now().Add(s.cacheTTL)}
		s.mu.Unlock()
	}
	return value, read, nil
}

// describe is a Secret Manager error: its code, never a message.
func describe(err error) error {
	switch status.Code(err) {
	case codes.NotFound:
		return errors.New("Secret Manager has no such secret or version")
	case codes.FailedPrecondition:
		return errors.New("the Secret Manager version is disabled or destroyed")
	}
	if _, ok := status.FromError(err); ok {
		return fmt.Errorf("Secret Manager answered %s", status.Code(err))
	}
	return err
}
