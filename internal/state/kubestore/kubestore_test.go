package kubestore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/keys/local"
	"github.com/hugr-lab/tresor-server/internal/state"
	"github.com/hugr-lab/tresor-server/internal/state/statetest"
)

var (
	ctx = context.Background()
	// cfg reaches the test's API server (envtest), nil when there is none: KUBEBUILDER_ASSETS unset.
	cfg *rest.Config
)

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("CI") != "" {
			fmt.Println("kubestore: KUBEBUILDER_ASSETS is not set on CI: the Kubernetes store must be tested there")
			os.Exit(1)
		}
		fmt.Println("kubestore: KUBEBUILDER_ASSETS is not set (setup-envtest): the Kubernetes store's tests are skipped")
		os.Exit(m.Run())
	}
	_, file, _, _ := runtime.Caller(0)
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join(filepath.Dir(file), "..", "..", "..", "deploy", "helm", "tresor-server", "crds")},
		ErrorIfCRDPathMissing: true,
	}
	var err error
	if cfg, err = env.Start(); err != nil {
		fmt.Println("envtest:", err)
		os.Exit(1)
	}
	code := m.Run()
	env.Stop()
	os.Exit(code)
}

func kek(t *testing.T, b byte) keys.KeyWrapper {
	t.Helper()
	w, err := local.New(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// namespace is a fresh namespace for one test.
func namespace(t *testing.T) string {
	t.Helper()
	if cfg == nil {
		t.Skip("no API server: KUBEBUILDER_ASSETS is not set")
	}
	raw := make([]byte, 4)
	rand.Read(raw)
	ns := "t-" + hex.EncodeToString(raw)
	cs := kubernetes.NewForConfigOrDie(cfg)
	if _, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	return ns
}

func openIn(t *testing.T, ns string, w keys.KeyWrapper, instance string) *Store {
	t.Helper()
	s, err := Open(ctx, cfg, w, Options{Namespace: ns, Instance: instance})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestKubernetes(t *testing.T) {
	statetest.Run(t, func(t *testing.T) statetest.Handles {
		ns := namespace(t)
		return statetest.Handles{First: openIn(t, ns, kek(t, 1), ""), Replicas: true,
			Another: func() state.Store { return openIn(t, ns, kek(t, 1), "") }}
	})
}

// a cluster with no CRDs, or another version of them: the service does not start
func TestSchema(t *testing.T) {
	if cfg == nil {
		t.Skip("no API server: KUBEBUILDER_ASSETS is not set")
	}
	if err := checkSchema(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	saved := allKinds
	defer func() { allKinds = saved }()
	allKinds = append(allKinds, kind{"TresorFuture", "tresorfutures"})
	if err := checkSchema(ctx, cfg); err == nil || !strings.Contains(err.Error(), "tresorfutures") {
		t.Fatalf("a kind not served: %v", err)
	}
}
