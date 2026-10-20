package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/testidp"
)

// a cluster's ServiceAccount issuer (spec 026): TLS under the cluster's own CA, its discovery and keys served
// to an authenticated account only - the service trusts ca_file and sends discovery_token_file's token
func TestClusterIssuer(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}}
	var unauthorized int
	srv := httptest.NewTLSServer(nil)
	t.Cleanup(srv.Close)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sa-token" {
			unauthorized++
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "jwks_uri": srv.URL + "/openid/v1/jwks",
				"response_types_supported": []string{"id_token"}, "subject_types_supported": []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/openid/v1/jwks":
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	})
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	tokenFile := filepath.Join(dir, "token")
	_ = os.WriteFile(tokenFile, []byte("sa-token\n"), 0o600)
	cfg := config.Issuer{Issuer: srv.URL, Audience: "duckdb-secrets", Algorithms: []string{"RS256"},
		Service: &config.ServiceRule{Claim: "kubernetes.io", ClientClaim: "sub"}, CAFile: ca, DiscoveryTokenFile: tokenFile}
	token := testidp.Sign(t, key, "k1", jose.RS256, testidp.Claims{"iss": srv.URL,
		"sub": "system:serviceaccount:hugr:hugr-init", "aud": []string{"duckdb-secrets"},
		"exp": time.Now().Add(time.Hour).Unix(), "kubernetes.io": map[string]any{"namespace": "hugr"}})
	v := NewVerifier([]config.Issuer{cfg})
	c, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verified: %v", err)
	}
	if !c.Has("client:system:serviceaccount:hugr:hugr-init") || c.Owner() != "subject:"+srv.URL+"|system:serviceaccount:hugr:hugr-init" {
		t.Fatalf("principals: %v", c.Principals)
	}
	if err := v.CheckIssuer(context.Background(), srv.URL); err != nil || unauthorized != 0 {
		t.Fatalf("readiness, with the token: %v (%d refused)", err, unauthorized)
	}
	// without the token: refused by the issuer, so no verification
	cfg.DiscoveryTokenFile = ""
	if _, err := NewVerifier([]config.Issuer{cfg}).Verify(context.Background(), token); err == nil || unauthorized == 0 {
		t.Fatal("verified without the token")
	}
	// without the CA: the TLS handshake fails
	cfg.DiscoveryTokenFile, cfg.CAFile = tokenFile, ""
	if _, err := NewVerifier([]config.Issuer{cfg}).Verify(context.Background(), token); err == nil {
		t.Fatal("verified without the CA")
	}
}
