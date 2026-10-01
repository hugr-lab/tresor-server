package main

import (
	"strings"
	"testing"

	"github.com/hugr-lab/tresor-server/internal/config"
)

// the service's own namespace holds its own credentials: no reference reads there
func TestOwnNamespaceRefused(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	cfg := &config.Config{State: config.State{Kind: "kubernetes", Namespace: "tresor"},
		Material: config.Material{K8s: config.K8s{Allow: []config.K8sAllow{{Namespace: "tresor"}}}}}
	if _, err := materialResolver(cfg); err == nil || !strings.Contains(err.Error(), "own namespace") {
		t.Fatalf("the service's own namespace: %v", err)
	}
}

// a password reference that does not parse stops the service at start, not at its first connection
func TestPasswordRefParsedAtStart(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBECONFIG", "/nonexistent")
	for _, ref := range []string{"ref+k8s://DB/pg/password", "ref+k8s://db/pg", "ref+k8s://db/pg/../x"} {
		cfg := &config.Config{State: config.State{PasswordRef: ref}}
		if _, err := passwordResolver(cfg, ref); err == nil || !strings.Contains(err.Error(), "state.password_ref") {
			t.Errorf("%s: %v", ref, err)
		}
	}
}
