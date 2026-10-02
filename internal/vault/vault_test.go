package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/hugr-lab/tresor-server/internal/vault/vaulttest"
)

var ctx = context.Background()

func TestAddress(t *testing.T) {
	for _, addr := range []string{"http://vault.example:8200", "ftp://x", "https://u:p@vault.example", "https://vault?x=1", ""} {
		if _, err := New(Config{Address: addr, Auth: Auth{Method: "token_file", TokenFile: "/t"}}); err == nil {
			t.Errorf("%q: accepted", addr)
		}
	}
	for _, auth := range []Auth{{Method: "jwt", Role: "r"}, {Method: "kubernetes"}, {Method: "approle"}, {Method: "token_file"}} {
		if _, err := New(Config{Address: "https://vault.example", Auth: auth}); err == nil {
			t.Errorf("%+v: accepted", auth)
		}
	}
}

// a JWT login (the projected token's way), against each server given; a token revoked is replaced by a
// new login, once; a token file is read again when it changes
func TestLogin(t *testing.T) {
	for _, srv := range vaulttest.Servers(t) {
		t.Run(srv.Name, func(t *testing.T) {
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
			mount := srv.Mount(t, "jwt")
			transit := srv.Mount(t, "transit")
			srv.Call(t, "POST", transit+"/keys/k", map[string]any{"type": "aes256-gcm96"}, nil)
			srv.Call(t, "PUT", "sys/policies/acl/"+mount, map[string]any{"policy": `path "` + transit + `/keys/k" { capabilities = ["read"] }`}, nil)
			srv.Call(t, "POST", "auth/"+mount+"/config", map[string]any{
				"jwt_validation_pubkeys": []string{string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}}, nil)
			srv.Call(t, "POST", "auth/"+mount+"/role/tresor", map[string]any{"role_type": "jwt", "bound_audiences": []string{"vault"},
				"user_claim": "sub", "token_policies": []string{mount}, "token_ttl": "10m"}, nil)
			signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
			token, _ := jwt.Signed(signer).Claims(jwt.Claims{Subject: "system:serviceaccount:tresor:tresor",
				Audience: jwt.Audience{"vault"}, Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)), IssuedAt: jwt.NewNumericDate(time.Now())}).Serialize()
			jwtFile := filepath.Join(t.TempDir(), "jwt")
			_ = os.WriteFile(jwtFile, []byte(token), 0o600)
			c, err := New(Config{Address: srv.Address, Auth: Auth{Method: "jwt", Mount: mount, Role: "tresor", JWTFile: jwtFile}})
			if err != nil {
				t.Fatal(err)
			}
			read := func() error { return c.Do(ctx, "GET", transit+"/keys/k", nil, nil) }
			if err := read(); err != nil {
				t.Fatalf("after a JWT login: %v", err)
			}
			first := c.token
			srv.Call(t, "POST", "auth/token/revoke", map[string]string{"token": first}, nil)
			if err := read(); err != nil || c.token == first {
				t.Fatalf("a revoked token, logged in again: %v", err)
			}
			// what the policy does not give is refused, and says so without a token
			err = c.Do(ctx, "GET", "sys/mounts", nil, nil)
			var ve *Error
			if !errors.As(err, &ve) || ve.Status != 403 || strings.Contains(err.Error(), c.token) {
				t.Fatalf("outside the policy: %v", err)
			}
			// a token the role does not accept: no login
			other, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: mustKey()}, nil)
			bad, _ := jwt.Signed(other).Claims(jwt.Claims{Subject: "x", Audience: jwt.Audience{"vault"},
				Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour))}).Serialize()
			_ = os.WriteFile(jwtFile, []byte(bad), 0o600)
			c2, _ := New(Config{Address: srv.Address, Auth: Auth{Method: "jwt", Mount: mount, Role: "tresor", JWTFile: jwtFile}})
			if err := c2.Do(ctx, "GET", transit+"/keys/k", nil, nil); err == nil {
				t.Fatal("a login with a key Vault does not know")
			}
			// token_file: read again when it changes
			tf := filepath.Join(t.TempDir(), "token")
			_ = os.WriteFile(tf, []byte("not-a-token"), 0o600)
			c3, _ := New(Config{Address: srv.Address, Auth: Auth{Method: "token_file", TokenFile: tf}})
			if err := c3.Do(ctx, "GET", transit+"/keys/k", nil, nil); err == nil {
				t.Fatal("a token Vault does not know")
			}
			time.Sleep(10 * time.Millisecond)
			_ = os.WriteFile(tf, []byte(srv.Token), 0o600)
			_ = os.Chtimes(tf, time.Now(), time.Now().Add(time.Second))
			if err := c3.Do(ctx, "GET", transit+"/keys/k", nil, nil); err != nil {
				t.Fatalf("the token file, renewed by its agent: %v", err)
			}
		})
	}
}

func mustKey() *ecdsa.PrivateKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return k
}
