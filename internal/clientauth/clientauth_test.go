package clientauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var ctx = context.Background()

func write(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// verify checks an assertion's signature under pub and returns its claims
func verify(t *testing.T, assertion string, pub any, alg jose.SignatureAlgorithm) (jwt.Claims, string) {
	t.Helper()
	tok, err := jwt.ParseSigned(assertion, []jose.SignatureAlgorithm{alg})
	if err != nil {
		t.Fatal(err)
	}
	var c jwt.Claims
	if err := tok.Claims(pub, &c); err != nil {
		t.Fatalf("the signature: %v", err)
	}
	return c, tok.Headers[0].KeyID
}

// ZITADEL's key file: its keyId and clientId come with the key; an assertion per call, a fresh jti each
func TestZitadelKeyFile(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	file, _ := json.Marshal(map[string]string{"type": "application", "keyId": "kid-1", "clientId": "svc@project",
		"appId": "123", "key": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))})
	signer, kid, clientID, err := KeyFile(write(t, "zitadel.json", file))
	if err != nil || kid != "kid-1" || clientID != "svc@project" || signer.Alg() != "RS256" {
		t.Fatalf("%v %q %q %v", signer, kid, clientID, err)
	}
	src := JWT(clientID, kid, Audience{Issuer: "https://acme.zitadel.cloud"}, signer)
	a1, err := src(ctx, "https://acme.zitadel.cloud/oauth/v2/token")
	if err != nil {
		t.Fatal(err)
	}
	c, gotKID := verify(t, a1, &key.PublicKey, jose.RS256)
	if gotKID != "kid-1" || c.Issuer != "svc@project" || c.Subject != "svc@project" ||
		!c.Audience.Contains("https://acme.zitadel.cloud") || c.ID == "" ||
		c.Expiry.Time().Sub(time.Now()) > 6*time.Minute || c.Expiry.Time().Before(time.Now()) {
		t.Fatalf("the claims: %+v", c)
	}
	a2, _ := src(ctx, "")
	if c2, _ := verify(t, a2, &key.PublicKey, jose.RS256); c2.ID == c.ID {
		t.Fatal("a jti twice")
	}
}

// a PEM EC key signs ES256 (r and s, as JWS has it); Entra's audience is the token endpoint
func TestPEMKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	signer, kid, clientID, err := KeyFile(write(t, "key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	if err != nil || kid != "" || clientID != "" || signer.Alg() != "ES256" {
		t.Fatalf("%v %q %q %v", signer, kid, clientID, err)
	}
	a, err := JWT("app", "x5t", Audience{Issuer: "https://login", TokenEndpoint: true}, signer)(ctx, "https://login/token")
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := verify(t, a, &key.PublicKey, jose.ES256); !c.Audience.Contains("https://login/token") {
		t.Fatalf("the token endpoint as the audience: %v", c.Audience)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ = x509.MarshalPKCS8PrivateKey(p384)
	if _, _, _, err := KeyFile(write(t, "p384.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))); err == nil {
		t.Fatal("a P-384 key for ES256")
	}
	if _, _, _, err := KeyFile(write(t, "junk.pem", []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))); err == nil ||
		strings.Contains(err.Error(), "asn1") {
		t.Fatalf("a key that does not read, said without the parser's text: %v", err)
	}
}

// a projected token is read at each request: the kubelet's rotation is seen at once
func TestFile(t *testing.T) {
	p := write(t, "token", []byte("first\n"))
	src := File(p)
	if a, err := src(ctx, ""); err != nil || a != "first" {
		t.Fatalf("%q %v", a, err)
	}
	_ = os.WriteFile(p, []byte("rotated"), 0o600)
	if a, _ := src(ctx, ""); a != "rotated" {
		t.Fatalf("after rotation: %q", a)
	}
	_ = os.WriteFile(p, nil, 0o600)
	if _, err := src(ctx, ""); err == nil {
		t.Fatal("an empty token")
	}
}
