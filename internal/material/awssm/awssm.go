// Package awssm resolves `ref+aws://<secret>[#<field>][?version=<id>]` (spec 012): an AWS Secrets Manager
// secret's string, or one field of a JSON secret, read with the service's AWS identity in the source's region
// and account (a named source may assume a role in another), within an allowlist of name prefixes. The request
// is built from the parsed parts, never from the text.
package awssm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"

	"github.com/hugr-lab/tresor-server/internal/material"
)

// Getter reads a secret's value: secretsmanager.Client, or a fake in tests.
type Getter interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// Source resolves aws references.
type Source struct {
	name     string // the scheme: "aws", or a named source's (spec 008)
	sm       Getter
	prefixes []string // the allowlist: names starting with one of them; empty - none is read
	all      bool     // the allowlist lists the source with no prefix: every secret
	cacheTTL time.Duration

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	value, version string
	until          time.Time
}

// New returns a source over the allowlist: prefixes, or every secret with all; cacheTTL keeps a value read
// that long (0: read at every fetch).
func New(sm Getter, prefixes []string, all bool, cacheTTL time.Duration) *Source {
	return &Source{name: "aws", sm: sm, prefixes: prefixes, all: all, cacheTTL: cacheTTL, cache: map[string]cached{}}
}

// Named is the source under another name (spec 008): ref+<name>://.
func (s *Source) Named(name string) *Source {
	s.name = name
	return s
}

func (s *Source) Scheme() string { return s.name }
func (s *Source) Kind() string   { return "aws" }

func (s *Source) allowlist() string {
	if s.name == "aws" {
		return "material.aws.allow"
	}
	return "material.sources[" + s.name + "].allow"
}

var (
	// a Secrets Manager name: letters, digits and /_+=.@- (an ARN is not accepted: the region and the account
	// are the source's)
	secretName = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]{1,512}$`)
	fieldName  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,256}$`)
	versionID  = regexp.MustCompile(`^[A-Za-z0-9-]{32,64}$`)
)

// Parse checks <secret>[#<field>][?version=<id>] and the allowlist.
func (s *Source) Parse(text string) (material.Ref, error) {
	usage := fmt.Errorf("ref+%s://<secret>[#<field>][?version=<id>]", s.name)
	rest, query, hasQuery := strings.Cut(text, "?")
	name, field, hasField := strings.Cut(rest, "#")
	ref := material.Ref{Scheme: s.name, Kind: "aws", Name: name, Key: field}
	if hasQuery {
		v, ok := strings.CutPrefix(query, "version=")
		if !ok || !versionID.MatchString(v) {
			return material.Ref{}, errors.New("a Secrets Manager reference's only query is ?version=<version id>")
		}
		ref.Version = v
	}
	switch {
	case name == "" || strings.Contains(name, "#") || strings.HasPrefix(name, "arn:"):
		return material.Ref{}, usage
	case !secretName.MatchString(name) || strings.Contains(name, "//") || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/"):
		return material.Ref{}, errors.New("a Secrets Manager secret's name is 1 to 512 letters, digits or /_+=.@- (no empty segment)")
	case hasField && !fieldName.MatchString(field):
		return material.Ref{}, errors.New("a JSON secret's field is 1 to 256 letters, digits or _.-")
	case !s.allowed(ref):
		return material.Ref{}, fmt.Errorf("%s is outside the allowlist (%s)", ref, s.allowlist())
	}
	return ref, nil
}

func (s *Source) allowed(ref material.Ref) bool {
	if s.all {
		return true
	}
	for _, p := range s.prefixes {
		if strings.HasPrefix(ref.Name, p) { // names are case-sensitive in Secrets Manager
			return true
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
	s.mu.Unlock()
	in := &secretsmanager.GetSecretValueInput{SecretId: aws.String(ref.Name)}
	if ref.Version != "" {
		in.VersionId = aws.String(ref.Version)
	}
	out, err := s.sm.GetSecretValue(ctx, in)
	if err != nil {
		return "", "", describe(err)
	}
	if out.SecretString == nil {
		return "", "", errors.New("the Secrets Manager secret is binary: a reference is a text value")
	}
	value := *out.SecretString
	if ref.Key != "" {
		var fields map[string]any
		if err := json.Unmarshal([]byte(value), &fields); err != nil {
			return "", "", errors.New("the Secrets Manager secret is not a JSON object: a #field needs one")
		}
		v, ok := fields[ref.Key]
		if !ok {
			return "", "", fmt.Errorf("the Secrets Manager secret has no field %s", ref.Key)
		}
		switch t := v.(type) {
		case string:
			value = t
		case float64, bool:
			b, _ := json.Marshal(t)
			value = string(b)
		default:
			return "", "", fmt.Errorf("the field %s is not a text, a number or a boolean", ref.Key)
		}
	}
	if !utf8.ValidString(value) {
		return "", "", errors.New("the Secrets Manager secret is not UTF-8 text")
	}
	version := aws.ToString(out.VersionId)
	if s.cacheTTL > 0 {
		s.mu.Lock()
		s.cache[key] = cached{value: value, version: version, until: time.Now().Add(s.cacheTTL)}
		s.mu.Unlock()
	}
	return value, version, nil
}

// describe is a Secrets Manager error: its code, never a message.
func describe(err error) error {
	var notFound *types.ResourceNotFoundException
	if errors.As(err, &notFound) {
		return errors.New("Secrets Manager has no such secret or version")
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		return fmt.Errorf("Secrets Manager answered %s", api.ErrorCode())
	}
	return err
}
