package k8s

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/hugr-lab/tresor-server/internal/material"
)

var (
	ctx = context.Background()
	// cfg reaches the test's API server (envtest), nil when there is none: KUBEBUILDER_ASSETS unset.
	cfg *rest.Config
)

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("CI") != "" {
			fmt.Println("k8s: KUBEBUILDER_ASSETS is not set on CI")
			os.Exit(1)
		}
		os.Exit(m.Run())
	}
	env := &envtest.Environment{}
	var err error
	if cfg, err = env.Start(); err != nil {
		fmt.Println("envtest:", err)
		os.Exit(1)
	}
	code := m.Run()
	env.Stop()
	os.Exit(code)
}

// fake is a cluster's Secrets: namespace/name -> data
type fake map[string]map[string][]byte

func (f fake) Get(_ context.Context, namespace, name string) (map[string][]byte, string, error) {
	data, ok := f[namespace+"/"+name]
	if !ok {
		return nil, "", errors.New("the Kubernetes API answered 404 NotFound")
	}
	return data, "42", nil
}

var allow = []Allow{{Namespace: "data-team", Prefixes: []string{"duckdb-", "lake."}}, {Namespace: "open"}}

func TestParse(t *testing.T) {
	s := NewWithGetter(allow, fake{})
	for text, want := range map[string]string{
		"data-team/duckdb-s3/secret":           "ref+k8s://data-team/duckdb-s3/secret",
		"data-team/lake.prod/AWS_SECRET.key-1": "ref+k8s://data-team/lake.prod/AWS_SECRET.key-1",
		"open/anything/k":                      "ref+k8s://open/anything/k",
	} {
		ref, err := s.Parse(text)
		if err != nil || ref.String() != want {
			t.Errorf("%s: %v %v", text, ref, err)
		}
	}
	for _, text := range []string{
		"data-team/duckdb-s3",                             // no key
		"data-team/duckdb-s3/k/x",                         // another segment
		"data-team/DuckDB-s3/k",                           // Kubernetes names are lower-case: no case folding
		"Data-Team/duckdb-s3/k",                           // a namespace's name
		"data-team/other/k",                               // outside the prefixes
		"kube-system/duckdb-s3/k",                         // outside the namespaces
		"data-team/duckdb-s3/..",                          // no such key
		"data-team/duckdb-s3/a%2Fb",                       // no escapes
		"data-team/duckdb-s3/k?x=1",                       // no query
		"data-team/duckdb-%2E%2E/k",                       // no escapes in a name
		"/duckdb-s3/k",                                    // no namespace
		"data-team/duckdb-s3/" + strings.Repeat("k", 254), // a key too long
	} {
		if _, err := s.Parse(text); err == nil {
			t.Errorf("%s: accepted", text)
		}
	}
}

func TestResolve(t *testing.T) {
	cluster := fake{"data-team/duckdb-s3": {"secret": []byte("hunter2"), "bin": {0xff, 0xfe}}}
	s := NewWithGetter(allow, cluster)
	ref, err := s.Parse("data-team/duckdb-s3/secret")
	if err != nil {
		t.Fatal(err)
	}
	if v, version, err := s.Resolve(ctx, ref); err != nil || v != "hunter2" || version != "42" {
		t.Fatalf("resolved %q %q %v", v, version, err)
	}
	for what, ref := range map[string]material.Ref{
		"a missing key":    {Scheme: "k8s", Vault: "data-team", Name: "duckdb-s3", Key: "nope"},
		"not UTF-8":        {Scheme: "k8s", Vault: "data-team", Name: "duckdb-s3", Key: "bin"},
		"a missing Secret": {Scheme: "k8s", Vault: "data-team", Name: "duckdb-gone", Key: "secret"},
		// the allowlist again: the configuration may have changed since the write
		"outside the allowlist": {Scheme: "k8s", Vault: "kube-system", Name: "duckdb-s3", Key: "secret"},
	} {
		if v, _, err := s.Resolve(ctx, ref); err == nil || v != "" {
			t.Errorf("%s: %q %v", what, v, err)
		} else if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: the error holds the value", what)
		}
	}
}

// against a real API server: a Secret's key, its rotation seen at the next read, its errors
func TestAPIServer(t *testing.T) {
	if cfg == nil {
		t.Skip("no API server: KUBEBUILDER_ASSETS is not set")
	}
	cs := kubernetes.NewForConfigOrDie(cfg)
	if _, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "data-team"}},
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "duckdb-s3", Namespace: "data-team"},
		Data: map[string][]byte{"secret": []byte("hunter2")}}
	if _, err := cs.CoreV1().Secrets("data-team").Create(ctx, sec, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	s, err := New(allow, cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := material.New(s)
	if v, err := r.ResolveOne(ctx, "ref+k8s://data-team/duckdb-s3/secret"); err != nil || v != "hunter2" {
		t.Fatalf("resolved %q %v", v, err)
	}
	sec.Data["secret"] = []byte("rotated")
	if _, err := cs.CoreV1().Secrets("data-team").Update(ctx, sec, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if v, err := r.ResolveOne(ctx, "ref+k8s://data-team/duckdb-s3/secret"); err != nil || v != "rotated" {
		t.Fatalf("after a rotation %q %v", v, err)
	}
	_, err = r.ResolveOne(ctx, "ref+k8s://data-team/duckdb-gone/secret")
	if !errors.Is(err, material.ErrUnresolved) || !strings.Contains(err.Error(), "404 NotFound") {
		t.Fatalf("a missing Secret: %v", err)
	}
}
