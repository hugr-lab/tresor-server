// Package k8s resolves `ref+k8s://<namespace>/<secret>/<key>` (spec 003): one key of a Kubernetes Secret, read
// with the service's ServiceAccount, within an allowlist of namespaces and Secret-name prefixes. RBAC gives the
// service get on Secrets in the namespaces listed; the prefixes are the allowlist's alone.
package k8s

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	"github.com/hugr-lab/tresor-server/internal/material"
)

// Allow lets references read one namespace's Secrets whose names start with one of the prefixes (all, when none).
type Allow struct {
	Namespace string
	Prefixes  []string
}

// Getter reads a Secret: its data, and the resourceVersion observed.
type Getter interface {
	Get(ctx context.Context, namespace, name string) (data map[string][]byte, resourceVersion string, err error)
}

// Source resolves k8s references.
type Source struct {
	allow  []Allow
	getter Getter
}

// New returns a source over the allowlist, reading through cfg.
func New(allow []Allow, cfg *rest.Config) (*Source, error) {
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return NewWithGetter(allow, secrets{dyn}), nil
}

// NewWithGetter is New over a given getter (tests).
func NewWithGetter(allow []Allow, g Getter) *Source { return &Source{allow: allow, getter: g} }

func (s *Source) Scheme() string { return "k8s" }

var (
	keyName = regexp.MustCompile(`^[-._a-zA-Z0-9]{1,253}$`)
)

// Parse checks <namespace>/<secret>/<key>: Kubernetes' own rules for each, no escape, no other segment, no
// query - and the allowlist. Names are compared exactly, as Kubernetes has them.
func (s *Source) Parse(text string) (material.Ref, error) {
	parts := strings.Split(text, "/")
	if len(parts) != 3 {
		return material.Ref{}, errors.New("ref+k8s://<namespace>/<secret>/<key>")
	}
	ref := material.Ref{Scheme: "k8s", Vault: parts[0], Name: parts[1], Key: parts[2]}
	switch {
	case len(validation.IsDNS1123Label(ref.Vault)) > 0:
		return material.Ref{}, errors.New("a namespace's name is a DNS label: lower-case letters, digits and dashes")
	case len(validation.IsDNS1123Subdomain(ref.Name)) > 0:
		return material.Ref{}, errors.New("a Secret's name is a DNS subdomain: lower-case letters, digits, dashes and dots")
	case !keyName.MatchString(ref.Key) || ref.Key == "." || ref.Key == "..":
		return material.Ref{}, errors.New("a Secret's key is letters, digits, dashes, underscores and dots")
	case !s.allowed(ref):
		return material.Ref{}, fmt.Errorf("%s is outside the allowlist (material.k8s.allow)", ref)
	}
	return ref, nil
}

func (s *Source) allowed(ref material.Ref) bool {
	for _, a := range s.allow {
		if a.Namespace != ref.Vault {
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

// Resolve reads the key now; its version is the Secret's observed resourceVersion (an opaque revision).
func (s *Source) Resolve(ctx context.Context, ref material.Ref) (string, string, error) {
	if !s.allowed(ref) { // the allowlist again: a reference is never resolved outside it
		return "", "", fmt.Errorf("%s is outside the allowlist", ref)
	}
	data, version, err := s.getter.Get(ctx, ref.Vault, ref.Name)
	if err != nil {
		return "", "", err
	}
	value, ok := data[ref.Key]
	if !ok {
		return "", "", errors.New("the Secret has no such key")
	}
	if !utf8.Valid(value) {
		return "", "", errors.New("the Secret's key is not UTF-8 text: a reference is a VARCHAR value")
	}
	return string(value), version, nil
}

// secrets reads Secrets by the dynamic client: the typed one would link every built-in API type.
type secrets struct{ dyn dynamic.Interface }

var secretsResource = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}

func (g secrets) Get(ctx context.Context, namespace, name string) (map[string][]byte, string, error) {
	u, err := g.dyn.Resource(secretsResource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, "", describe(err)
	}
	raw, _ := u.Object["data"].(map[string]any)
	data := make(map[string][]byte, len(raw))
	for k, v := range raw {
		text, ok := v.(string)
		if !ok {
			return nil, "", errors.New("the Secret's data does not read")
		}
		b, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return nil, "", errors.New("the Secret's data does not read")
		}
		data[k] = b
	}
	return data, u.GetResourceVersion(), nil
}

// describe is an API error: its status and reason, never a body nor a message - a decoding error may quote the
// whole response, which for a Secret is its data.
func describe(err error) error {
	var status apierrors.APIStatus
	var urlErr *url.Error
	switch {
	case errors.As(err, &status):
		s := status.Status()
		return fmt.Errorf("the Kubernetes API answered %d %s", s.Code, s.Reason)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return errors.New("the Kubernetes API did not answer in time")
	case errors.As(err, &urlErr):
		return errors.New("the Kubernetes API is unreachable")
	}
	return errors.New("the Kubernetes API answered something unreadable")
}
