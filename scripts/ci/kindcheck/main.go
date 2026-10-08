// kindcheck is the chart's CI helper (scripts/ci/kind.sh), not shipped:
//
//	kindcheck issuer <dir> <issuer>        an OIDC issuer's static files: its discovery, its JWKS, its key
//	kindcheck smoke <dir> <issuer> <url> [<ref> <value>]
//	kindcheck keep <dir> <issuer> <url>    # a secret written and granted, kept (spec 011: a KEK move)
//	kindcheck kept <dir> <issuer> <url>    # that secret still read, its material whole
//	kindcheck kc <ca> <keycloak> <url>     # a token minted by Keycloak's exchange, the service authenticated by
//	                                       # its ServiceAccount token (federated client authentication); the
//	                                       # clients' secrets in KC_ADMIN_SECRET, KC_CALLER_SECRET
//	                                       through the protocol: an administrator writes a secret and grants
//	                                       its use, a user reads it, the administrator deletes it - the service
//	                                       is up on its store; with a reference, one that reads <value>
package main

import (
	"bytes"
	"encoding/base64"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const audience = "duckdb-secrets"

func main() {
	log.SetFlags(0)
	switch {
	case len(os.Args) == 4 && os.Args[1] == "issuer":
		issuer(os.Args[2], os.Args[3])
	case len(os.Args) == 5 && os.Args[1] == "smoke":
		smoke(os.Args[2], os.Args[3], os.Args[4], "", "")
	case len(os.Args) == 7 && os.Args[1] == "smoke":
		smoke(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6])
	case len(os.Args) == 5 && (os.Args[1] == "keep" || os.Args[1] == "kept"):
		keep(os.Args[1] == "keep", os.Args[2], os.Args[3], os.Args[4])
	case len(os.Args) == 5 && os.Args[1] == "kc":
		kc(os.Args[2], os.Args[3], os.Args[4])
	default:
		log.Fatal("usage: kindcheck issuer <dir> <issuer> | kindcheck smoke|keep|kept <dir> <issuer> <url> | kindcheck kc <ca> <keycloak> <url>")
	}
}

func issuer(dir, iss string) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	must(os.MkdirAll(dir, 0o700))
	must(os.WriteFile(filepath.Join(dir, "key.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600))
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	must(os.WriteFile(filepath.Join(dir, "jwks"), jwks, 0o644))
	discovery, _ := json.Marshal(map[string]any{"issuer": iss, "jwks_uri": iss + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"}, "response_types_supported": []string{"code"},
		"subject_types_supported": []string{"public"}})
	must(os.WriteFile(filepath.Join(dir, "openid-configuration"), discovery, 0o644))
}

func token(dir, iss, sub string, roles ...string) string {
	raw, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	must(err)
	block, _ := pem.Decode(raw)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	must(err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	must(err)
	now := time.Now()
	t, err := jwt.Signed(signer).Claims(map[string]any{"iss": iss, "sub": sub, "aud": audience, "azp": "duckdb",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "roles": roles}).Serialize()
	must(err)
	return t
}

func smoke(dir, iss, url, ref, want string) {
	admin, user := token(dir, iss, "admin", "secrets_admin"), token(dir, iss, "alice", "analysts")
	call := func(method, path, tok, body string, want int) string {
		req, err := http.NewRequest(method, strings.TrimSuffix(url, "/")+path, bytes.NewBufferString(body))
		must(err)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		must(err)
		defer res.Body.Close()
		out, _ := io.ReadAll(res.Body)
		if res.StatusCode != want {
			log.Fatalf("kindcheck: %s %s: %d, want %d: %s", method, path, res.StatusCode, want, out)
		}
		return string(out)
	}
	call("GET", "/v1/whoami", admin, "", 200)
	call("PUT", "/v1/secrets/lake", admin, `{"type":"s3","provider":"config","scope":["s3://lake"],
		"params":{"key_id":"AKIA","secret":{"type":"VARCHAR","value":"kind-material"}},"redact_keys":["secret"]}`, 201)
	call("PUT", "/v1/secrets/lake/grants/analysts", admin, `{"principal":"role:analysts","verbs":["use"]}`, 200)
	if got := call("GET", "/v1/secrets/lake", user, "", 200); !strings.Contains(got, "kind-material") {
		log.Fatal("kindcheck: the user's read holds no material")
	}
	call("GET", "/v1/secrets/lake", token(dir, iss, "bob", "others"), "", 404)
	call("DELETE", "/v1/secrets/lake", admin, "", 204)
	call("GET", "/v1/secrets/lake", user, "", 404)
	fmt.Println("kindcheck: a secret written, granted, read and deleted through the protocol")
	// a variable (spec 004): the same rules, its own routes
	call("PUT", "/v1/variables/region", admin, `{"value":"eu-west"}`, 201)
	call("PUT", "/v1/variables/region/grants/analysts", admin, `{"principal":"role:analysts","verbs":["use"]}`, 200)
	if got := call("GET", "/v1/variables/region", user, "", 200); !strings.Contains(got, `"value":"eu-west"`) {
		log.Fatal("kindcheck: the user's read of the variable holds no value")
	}
	call("DELETE", "/v1/variables/region", admin, "", 204)
	fmt.Println("kindcheck: a variable written, granted, read and deleted")
	if ref == "" {
		return
	}
	call("PUT", "/v1/secrets/byref", admin, `{"type":"s3","provider":"config","scope":["s3://ref"],
		"params":{"key_id":"AKIA","secret":"`+ref+`"},"redact_keys":[]}`, 201)
	call("PUT", "/v1/secrets/byref/grants/analysts", admin, `{"principal":"role:analysts","verbs":["use"]}`, 200)
	if got := call("GET", "/v1/secrets/byref", user, "", 200); !strings.Contains(got, want) {
		log.Fatal("kindcheck: the reference did not read its value")
	}
	call("PUT", "/v1/variables/byref", admin, `{"value":"`+ref+`"}`, 201)
	call("PUT", "/v1/variables/byref/grants/analysts", admin, `{"principal":"role:analysts","verbs":["use"]}`, 200)
	if got := call("GET", "/v1/variables/byref", user, "", 200); !strings.Contains(got, want) || !strings.Contains(got, `"sensitive":true`) {
		log.Fatal("kindcheck: the variable's reference did not read its value, sensitive")
	}
	call("DELETE", "/v1/secrets/byref", admin, "", 204)
	call("DELETE", "/v1/variables/byref", admin, "", 204)
	fmt.Println("kindcheck: a reference resolved at the read, in a secret and in a variable")
}

// keep writes a secret and grants it (write), or reads it back (!write): across a move to another KEK, the
// material written before reads after
func keep(write bool, dir, iss, url string) {
	call := func(method, path, tok, body string, want int) string {
		req, err := http.NewRequest(method, strings.TrimSuffix(url, "/")+path, bytes.NewBufferString(body))
		must(err)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		must(err)
		defer res.Body.Close()
		out, _ := io.ReadAll(res.Body)
		if res.StatusCode != want {
			log.Fatalf("kindcheck: %s %s: %d, want %d: %s", method, path, res.StatusCode, want, out)
		}
		return string(out)
	}
	if write {
		admin := token(dir, iss, "admin", "secrets_admin")
		call("PUT", "/v1/secrets/kept", admin, `{"type":"s3","provider":"config","scope":["s3://kept"],
		"params":{"secret":{"type":"VARCHAR","value":"kept-material"}},"redact_keys":["secret"]}`, 201)
		call("PUT", "/v1/secrets/kept/grants/analysts", admin, `{"principal":"role:analysts","verbs":["use"]}`, 200)
		fmt.Println("kindcheck: a secret written to keep")
		return
	}
	if got := call("GET", "/v1/secrets/kept", token(dir, iss, "alice", "analysts"), "", 200); !strings.Contains(got, "kept-material") {
		log.Fatal("kindcheck: the kept secret's material did not read")
	}
	fmt.Println("kindcheck: the kept secret read, its material whole")
}

// kc: through the service, a token_exchange secret an administrator wrote and granted, read by a caller - minted
// by Keycloak's token exchange for the caller, the service logged in at Keycloak with its projected
// ServiceAccount token (spec 006: client_auth file; Keycloak's federated client authentication, a Kubernetes
// identity provider). Tokens come from Keycloak itself (client credentials), reached by a port-forward: TLS of
// the run's CA, the name keycloak.kc.svc.
func kc(caFile, keycloak, url string) {
	pemCA, err := os.ReadFile(caFile)
	must(err)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemCA)
	kcHTTP := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "keycloak.kc.svc"}}}
	token := func(client, secret string) string {
		form := neturl.Values{"grant_type": {"client_credentials"}, "client_id": {client}, "client_secret": {secret}}
		res, err := kcHTTP.PostForm(strings.TrimSuffix(keycloak, "/")+"/realms/tresor/protocol/openid-connect/token", form)
		must(err)
		defer res.Body.Close()
		var out struct {
			AccessToken string `json:"access_token"`
		}
		if res.StatusCode != 200 || json.NewDecoder(res.Body).Decode(&out) != nil || out.AccessToken == "" {
			log.Fatalf("kindcheck: Keycloak gave %s no token: %d", client, res.StatusCode)
		}
		return out.AccessToken
	}
	admin, caller := token("ci-admin", os.Getenv("KC_ADMIN_SECRET")), token("ci-caller", os.Getenv("KC_CALLER_SECRET"))
	call := func(method, path, tok, body string, want int) string {
		req, err := http.NewRequest(method, strings.TrimSuffix(url, "/")+path, bytes.NewBufferString(body))
		must(err)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		must(err)
		defer res.Body.Close()
		out, _ := io.ReadAll(res.Body)
		if res.StatusCode != want {
			log.Fatalf("kindcheck: %s %s: %d, want %d: %s", method, path, res.StatusCode, want, out)
		}
		return string(out)
	}
	call("PUT", "/v1/secrets/lake-api", admin, `{"type":"http","provider":"token_exchange","scope":["https://lake.example"],
		"params":{"audience":"lake-api"},"redact_keys":[]}`, 201)
	call("PUT", "/v1/secrets/lake-api/grants/analysts", admin, `{"principal":"role:analysts","verbs":["use"]}`, 200)
	var got struct {
		Params struct {
			BearerToken string `json:"bearer_token"`
		} `json:"params"`
	}
	must(json.Unmarshal([]byte(call("GET", "/v1/secrets/lake-api", caller, "", 200)), &got))
	parts := strings.Split(got.Params.BearerToken, ".")
	if len(parts) != 3 || got.Params.BearerToken == caller {
		log.Fatal("kindcheck: no token minted for the caller")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	must(err)
	var claims struct {
		Aud any    `json:"aud"`
		Azp string `json:"azp"`
	}
	must(json.Unmarshal(payload, &claims))
	if !strings.Contains(fmt.Sprint(claims.Aud), "lake-api") || claims.Azp != audience {
		log.Fatalf("kindcheck: the minted token: aud %v, azp %s", claims.Aud, claims.Azp)
	}
	call("DELETE", "/v1/secrets/lake-api", admin, "", 204)
	fmt.Println("kindcheck: a token minted by Keycloak's exchange, the service logged in with its ServiceAccount token")
}

func must(err error) {
	if err != nil {
		log.Fatalf("kindcheck: %v", err)
	}
}
