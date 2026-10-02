package vaultkek

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/hugr-lab/tresor-server/internal/clientauth"
	"github.com/hugr-lab/tresor-server/internal/vault"
	"github.com/hugr-lab/tresor-server/internal/vault/vaulttest"
)

// the exchange's assertion signed in Transit, on every server given: a key made there (RS256, ES256) checked with
// its public key, and an IdP's key imported (ZITADEL's way: BYOK) checked with the key the IdP holds
func TestSigner(t *testing.T) {
	for _, srv := range vaulttest.Servers(t) {
		t.Run(srv.Name, func(t *testing.T) {
			mount := srv.Mount(t, "transit")
			client, err := vault.New(vault.Config{Address: srv.Address, Auth: vault.Auth{Method: "token_file", TokenFile: srv.TokenFile(t)}})
			if err != nil {
				t.Fatal(err)
			}
			publicKey := func(name string) crypto.PublicKey {
				var out struct {
					Data struct {
						Keys map[string]struct {
							PublicKey string `json:"public_key"`
						} `json:"keys"`
					} `json:"data"`
				}
				srv.Call(t, "GET", mount+"/keys/"+name, nil, &out)
				block, _ := pem.Decode([]byte(out.Data.Keys["1"].PublicKey))
				if block == nil {
					t.Fatal("no public key")
				}
				pub, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				return pub
			}
			for typ, alg := range map[string]jose.SignatureAlgorithm{"rsa-2048": jose.RS256, "rsa-3072": jose.RS256,
				"rsa-4096": jose.RS256, "ecdsa-p256": jose.ES256} {
				srv.Call(t, "POST", mount+"/keys/"+typ, map[string]any{"type": typ}, nil)
				signer, err := NewSigner(ctx, client, mount, typ)
				if err != nil {
					t.Fatal(err)
				}
				checkAssertion(t, signer, alg, publicKey(typ))
			}

			// a rotation: the running signer keeps v1 (the IdP's key, its kid); a new one (a restart) takes v2
			pinned, err := NewSigner(ctx, client, mount, "ecdsa-p256")
			if err != nil {
				t.Fatal(err)
			}
			v1 := publicKey("ecdsa-p256")
			srv.Call(t, "POST", mount+"/keys/ecdsa-p256/rotate", nil, nil)
			checkAssertion(t, pinned, jose.ES256, v1)
			if restarted, err := NewSigner(ctx, client, mount, "ecdsa-p256"); err != nil || restarted.version != 2 {
				t.Fatalf("after a restart: %v", err)
			}

			// ZITADEL makes the key; Transit imports it and signs with it, the file destroyed
			zitadel, _ := rsa.GenerateKey(rand.Reader, 2048)
			importKey(t, srv, mount, "zitadel", "rsa-2048", zitadel)
			signer, err := NewSigner(ctx, client, mount, "zitadel")
			if err != nil {
				t.Fatal(err)
			}
			checkAssertion(t, signer, jose.RS256, &zitadel.PublicKey)

			// a key that does not sign, and one that is not there
			srv.Call(t, "POST", mount+"/keys/aes", map[string]any{"type": "aes256-gcm96"}, nil)
			if _, err := NewSigner(ctx, client, mount, "aes"); err == nil {
				t.Fatal("an AES key signs")
			}
			srv.Call(t, "POST", mount+"/keys/p384", map[string]any{"type": "ecdsa-p384"}, nil)
			if _, err := NewSigner(ctx, client, mount, "p384"); err == nil {
				t.Fatal("a P-384 key signs ES256")
			}
			if _, err := NewSigner(ctx, client, mount, "missing"); err == nil {
				t.Fatal("a missing key")
			}
			if _, err := NewSigner(ctx, client, "..", "k"); err == nil {
				t.Fatal("an odd mount")
			}
		})
	}
}

func checkAssertion(t *testing.T, signer *Signer, alg jose.SignatureAlgorithm, pub crypto.PublicKey) {
	t.Helper()
	if signer.Alg() != string(alg) {
		t.Fatalf("alg %s, want %s", signer.Alg(), alg)
	}
	a, err := clientauth.JWT("app", clientauth.Header{KID: "k1"}, clientauth.Audience{Issuer: "https://idp"}, signer)(ctx, "https://idp/token")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.ParseSigned(a, []jose.SignatureAlgorithm{alg})
	if err != nil {
		t.Fatal(err)
	}
	var claims jwt.Claims
	if err := tok.Claims(pub, &claims); err != nil {
		t.Fatalf("%s: the signature does not verify: %v", alg, err)
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{Issuer: "app", Subject: "app", AnyAudience: jwt.Audience{"https://idp"},
		Time: time.Now()}, 0); err != nil || tok.Headers[0].KeyID != "k1" {
		t.Fatalf("%s: %v %+v", alg, err, tok.Headers[0])
	}
}

// importKey brings a private key into Transit (BYOK): wrapped by an ephemeral AES key (RFC 5649), which is
// wrapped by Transit's wrapping key (RSA-OAEP, SHA-256) - what `bao transit import` does
func importKey(t *testing.T, srv vaulttest.Server, mount, name, typ string, key crypto.Signer) {
	t.Helper()
	var wk struct {
		Data struct {
			PublicKey string `json:"public_key"`
		} `json:"data"`
	}
	srv.Call(t, "GET", mount+"/wrapping_key", nil, &wk)
	block, _ := pem.Decode([]byte(wk.Data.PublicKey))
	if block == nil {
		t.Fatal("no wrapping key")
	}
	wrapping, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ephemeral := make([]byte, 32)
	_, _ = rand.Read(ephemeral)
	wrappedEphemeral, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, wrapping.(*rsa.PublicKey), ephemeral, nil)
	if err != nil {
		t.Fatal(err)
	}
	ct := append(wrappedEphemeral, kwp(t, ephemeral, pkcs8)...)
	srv.Call(t, "POST", mount+"/keys/"+name+"/import", map[string]any{
		"ciphertext": base64.StdEncoding.EncodeToString(ct), "type": typ, "hash_function": "SHA256"}, nil)
}

// kwp is AES key wrap with padding (RFC 5649)
func kwp(t *testing.T, kek, plain []byte) []byte {
	t.Helper()
	b, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	a := make([]byte, 8)
	copy(a, []byte{0xA6, 0x59, 0x59, 0xA6})
	binary.BigEndian.PutUint32(a[4:], uint32(len(plain)))
	padded := append(append([]byte{}, plain...), make([]byte, (8-len(plain)%8)%8)...)
	n := len(padded) / 8
	if n == 1 {
		out := make([]byte, 16)
		b.Encrypt(out, append(a, padded...))
		return out
	}
	r := make([][]byte, n)
	for i := range r {
		r[i] = padded[i*8 : (i+1)*8]
	}
	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(buf, a)
			copy(buf[8:], r[i])
			b.Encrypt(buf, buf)
			step := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(buf[:8])^step)
			r[i] = append([]byte{}, buf[8:]...)
		}
	}
	out := append([]byte{}, a...)
	for _, ri := range r {
		out = append(out, ri...)
	}
	return out
}

// fake answers Transit's calls as told
type fake struct {
	keyType, signature string
	signErr            error
}

func (f fake) Do(_ context.Context, _, path string, _, out any) error {
	var answer string
	if strings.Contains(path, "/keys/") {
		answer = `{"data":{"type":"` + f.keyType + `","latest_version":3}}`
	} else {
		if f.signErr != nil {
			return f.signErr
		}
		answer = `{"data":{"signature":"` + f.signature + `"}}`
	}
	return json.Unmarshal([]byte(answer), out)
}

// a signature that is not the pinned version's, not of its encoding or length, or refused: no signer, never
// an empty signature; the error names the key, not the token
func TestSignerRefuses(t *testing.T) {
	es := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	if _, err := NewSigner(ctx, fake{keyType: "ecdsa-p256", signature: "vault:v3:" + es}, "transit", "k"); err != nil {
		t.Fatalf("a good one: %v", err)
	}
	for name, f := range map[string]fake{
		"another version":  {keyType: "ecdsa-p256", signature: "vault:v2:" + es},
		"no prefix":        {keyType: "ecdsa-p256", signature: es},
		"short":            {keyType: "ecdsa-p256", signature: "vault:v3:" + base64.RawURLEncoding.EncodeToString(make([]byte, 63))},
		"base64 for ES256": {keyType: "ecdsa-p256", signature: "vault:v3:" + base64.StdEncoding.EncodeToString(make([]byte, 65))},
		"url for RS256":    {keyType: "rsa-2048", signature: "vault:v3:" + es},
		"empty":            {keyType: "rsa-2048", signature: "vault:v3:"},
		"refused":          {keyType: "rsa-2048", signErr: &vault.Error{Status: 403, Msg: "permission denied"}},
	} {
		_, err := NewSigner(ctx, f, "transit", "k")
		if err == nil || !strings.Contains(err.Error(), "transit/k") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
