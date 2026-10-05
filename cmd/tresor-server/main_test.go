package main

import (
	"context"
	"strings"
	"testing"

	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/vault/vaulttest"
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

// a named vault source (spec 008) reads with its own Vault: material through it, and the database's password
// through it, outside its allowlist; the top-level vault: is another server
func TestNamedVaultSource(t *testing.T) {
	servers := vaulttest.Servers(t)
	if len(servers) < 2 {
		t.Skip("two servers are needed")
	}
	top, us := servers[0], servers[1]
	mount := us.Mount(t, "kv-v2")
	us.Call(t, "POST", mount+"/data/duckdb/lake", map[string]any{"data": map[string]any{"secret": "from-us"}}, nil)
	us.Call(t, "POST", mount+"/data/tresor/db", map[string]any{"data": map[string]any{"password": "pg-pass"}}, nil)
	login := func(s vaulttest.Server) config.Vault {
		return config.Vault{Address: s.Address, Auth: config.VaultAuth{Method: "token_file", TokenFile: s.TokenFile(t)}}
	}
	own := login(us)
	cfg := &config.Config{Vault: login(top), Material: config.Material{Sources: []config.NamedSource{{
		Name: "vault-us", Kind: "vault", Vault: &own, Allow: []config.SourceAllow{{Mount: mount, Prefixes: []string{"duckdb/"}}}}}}}
	r, err := materialResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := r.ResolveOne(context.Background(), "ref+vault-us://"+mount+"/duckdb/lake#secret"); err != nil || v != "from-us" {
		t.Fatalf("material: %q %v", v, err)
	}
	ref := "ref+vault-us://" + mount + "/tresor/db#password"
	if _, err := r.ResolveOne(context.Background(), ref); err == nil {
		t.Fatal("the password within material's allowlist")
	}
	pr, err := passwordResolver(cfg, ref)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := pr.ResolveOne(context.Background(), ref); err != nil || v != "pg-pass" {
		t.Fatalf("the password: %q %v", v, err)
	}
	if _, err := passwordResolver(cfg, "ref+nope://x/y#z"); err == nil {
		t.Fatal("a name no source has")
	}
}
