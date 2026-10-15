package api

import (
	"strings"
	"testing"
	"time"

	azkv "github.com/hugr-lab/tresor-server/internal/material/azurekeyvault"
	"github.com/hugr-lab/tresor-server/internal/testidp"
)

// generated values (spec 023): checked at the write, refused naming the parameter, never the value
func TestGeneratedValidation(t *testing.T) {
	f := newFixture(t, "")
	for name, params := range map[string]string{
		"no kind":            `{"bearer_token":"mint+secret-value"}`,
		"an unknown kind":    `{"bearer_token":"mint+vault://x"}`,
		"no audience":        `{"bearer_token":"mint+exchange://"}`,
		"a query not scope":  `{"bearer_token":"mint+exchange://echo-api?prompt=none"}`,
		"this service's own": `{"bearer_token":"mint+exchange://duckdb-secrets"}`,
		"no claim":           `{"bearer_token":"mint+claim://"}`,
		"a session claim":    `{"bearer_token":"mint+claim://sid"}`,
		"a login, not yet":   `{"bearer_token":"mint+login://crm#access_token"}`,
		"unclosed":           `{"bearer_token":"Bearer ${claim://sub"}`,
		"inside a MAP":       `{"extra_http_headers":{"type":"MAP(VARCHAR, VARCHAR)","value":{"X":"${claim://nonce}"}}}`,
	} {
		r := f.do("PUT", "/v1/secrets/g", f.admin, `{"type":"http","provider":"config","params":`+params+`}`)
		if r.status != 422 {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
		if strings.Contains(string(r.body), "secret-value") {
			t.Errorf("%s: the refusal names the value: %s", name, r.body)
		}
	}
	// literals only: escapes make no secret dynamic
	r := f.do("PUT", "/v1/secrets/lit", f.admin, `{"type":"http","provider":"config",
		"params":{"http_proxy":"mint++literal","http_proxy_username":"$${not}","other":"${nothing}"}}`)
	if r.status != 201 || r.json(t)["dynamic"] != false {
		t.Fatalf("escapes: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/lit/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	body := f.do("GET", "/v1/secrets/lit", f.alice, "").json(t)
	params := body["params"].(map[string]any)
	if params["http_proxy"] != "mint+literal" || params["http_proxy_username"] != "${not}" || params["other"] != "${nothing}" {
		t.Fatalf("literals unescaped: %v", params)
	}
	if body["expires_at"] != nil || len(body["redact_keys"].([]any)) != 0 {
		t.Fatalf("a static secret: %v %v", body["expires_at"], body["redact_keys"])
	}
}

const claimSecret = `{"type":"http","provider":"config","scope":["https://echo.example"],
  "params":{"bearer_token":"mint+claim://preferred_username",
    "extra_http_headers":{"type":"MAP(VARCHAR, VARCHAR)","value":{"X-User":"u=${claim://preferred_username}","X-Lit":"$${x}"}},
    "http_proxy":"mint++literal"}}`

// a claim of the caller's verified token, whole or inside a MAP; the secret dynamic in a list too (which opens
// no params); the provider the consumer's; the generated keys redacted
func TestGeneratedClaims(t *testing.T) {
	f := newFixture(t, "")
	if r := f.do("PUT", "/v1/secrets/who", f.admin, claimSecret); r.status != 201 || r.json(t)["dynamic"] != true {
		t.Fatalf("written: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/who/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	list := f.do("GET", "/v1/secrets", f.alice, "")
	if !strings.Contains(string(list.body), `"dynamic":true`) || !strings.Contains(string(list.body), `"provider":"config"`) {
		t.Fatalf("listed: %s", list.body)
	}
	r := f.do("GET", "/v1/secrets/who", f.alice, "")
	body := r.json(t)
	params := body["params"].(map[string]any)
	headers := params["extra_http_headers"].(map[string]any)["value"].(map[string]any)
	if params["bearer_token"] != "alice" || headers["X-User"] != "u=alice" || headers["X-Lit"] != "${x}" ||
		params["http_proxy"] != "mint+literal" {
		t.Fatalf("material: %s", r.body)
	}
	redact := body["redact_keys"].([]any)
	if len(redact) != 2 || redact[0] != "bearer_token" || redact[1] != "extra_http_headers" {
		t.Fatalf("redact_keys: %v", redact)
	}
	expires, err := time.Parse(time.RFC3339, body["expires_at"].(string))
	if err != nil || !expires.After(time.Now()) {
		t.Fatalf("expires_at: %v", body["expires_at"])
	}
	// a caller whose token has no such claim, or a claim shaped like a token: refused, never empty
	bob := f.idp.Token(t, testidp.Claims{"sub": "bob-id", "aud": []string{"duckdb-secrets"},
		"realm_access": map[string]any{"roles": []any{"analysts"}}})
	if r := f.do("GET", "/v1/secrets/who", bob, ""); r.status != 403 || r.problemType(t) != "mint_refused" {
		t.Fatalf("no claim: %d %s", r.status, r.body)
	}
	carol := f.idp.Token(t, testidp.Claims{"sub": "carol-id", "aud": []string{"duckdb-secrets"},
		"realm_access": map[string]any{"roles": []any{"analysts"}}, "preferred_username": "aaa.bbb.ccc"})
	if r := f.do("GET", "/v1/secrets/who", carol, ""); r.status != 403 {
		t.Fatalf("a token in a claim: %d %s", r.status, r.body)
	}
}

// under a delegation grant, a claim is the grant's user's - never the server's own
func TestGeneratedClaimsUnderGrant(t *testing.T) {
	f := newFixture(t, "")
	node := f.idp.Service(t, "duckdb-secrets", "node", "nodes")
	f.do("PUT", "/v1/secrets/who", f.admin, claimSecret)
	f.do("PUT", "/v1/secrets/who/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	g, r := f.grantFor(node, f.alice)
	if g == "" {
		t.Fatalf("exchange: %d %s", r.status, r.body)
	}
	r = f.do("GET", "/v1/secrets/who", node, "", "Delegation", g)
	if r.status != 200 || r.json(t)["params"].(map[string]any)["bearer_token"] != "alice" {
		t.Fatalf("the grant's user's claim: %d %s", r.status, r.body)
	}
	if r := f.do("GET", "/v1/secrets/who", node, ""); r.status != 403 {
		t.Fatalf("the node as itself has no such claim: %d %s", r.status, r.body)
	}
}

// a token for the caller, whole and inside a header; the token_exchange alias served with provider config
func TestGeneratedExchange(t *testing.T) {
	f := newFixture(t, "")
	r := f.do("PUT", "/v1/secrets/echo", f.admin, `{"type":"http","provider":"config","scope":["https://echo.example"],
		"params":{"bearer_token":"mint+exchange://echo-api",
		"extra_http_headers":{"type":"MAP(VARCHAR, VARCHAR)","value":{"X-Token":"Bearer ${exchange://echo-api}"}}}}`)
	if r.status != 201 {
		t.Fatalf("written: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/echo/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	bearer, body, r := f.mintedMaterial(f.alice)
	if bearer == "" {
		t.Fatalf("material: %d %s", r.status, r.body)
	}
	if c := claimsOf(t, bearer); c["sub"] != "alice-id" || c["aud"] != "echo-api" {
		t.Fatalf("alice's token for echo-api: %v", c)
	}
	headers := body["params"].(map[string]any)["extra_http_headers"].(map[string]any)["value"].(map[string]any)
	if headers["X-Token"] != "Bearer "+bearer || f.idp.Exchanges != 1 {
		t.Fatalf("one exchange, the same token in both: %v, %d exchanges", headers, f.idp.Exchanges)
	}
	if body["provider"] != "config" {
		t.Fatalf("provider: %v", body["provider"])
	}
	// the margin: what the client is told expires before the token, never after it
	expires, _ := time.Parse(time.RFC3339, body["expires_at"].(string))
	if exp := int64(claimsOf(t, bearer)["exp"].(float64)); !expires.Before(time.Unix(exp, 0)) {
		t.Fatalf("expires_at %v, the token's exp %d", expires, exp)
	}
	if strings.Contains(f.logs.String(), bearer) {
		t.Fatal("a token reached the log")
	}
	// the alias
	f.do("PUT", "/v1/secrets/alias", f.admin, mintedSecret)
	f.do("PUT", "/v1/secrets/alias/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	r = f.do("GET", "/v1/secrets/alias", f.alice, "")
	if r.status != 200 || r.json(t)["provider"] != "config" || r.json(t)["dynamic"] != true {
		t.Fatalf("the alias: %d %s", r.status, r.body)
	}
	if d := f.do("GET", "/.well-known/duckdb-secrets", "", ""); !strings.Contains(string(d.body), `"dynamic":true`) {
		t.Fatalf("discovery: %s", d.body)
	}
}

// a reference is read as it resolves: what a vault holds is never read as a generator
func TestGeneratedNotFromReferences(t *testing.T) {
	f := newFixture(t, "")
	v := &kvSecrets{values: map[string]string{"lake-s3": "${claim://preferred_username}"}}
	withVault(f, v, azkv.Allow{Vault: "corp-vault", Prefixes: []string{"lake-"}})
	if r := f.do("PUT", "/v1/secrets/lake", f.admin, refSecret); r.status != 201 || r.json(t)["dynamic"] != false {
		t.Fatalf("a reference: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/lake/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	r := f.do("GET", "/v1/secrets/lake", f.alice, "")
	secret := r.json(t)["params"].(map[string]any)["secret"].(map[string]any)
	if secret["value"] != "${claim://preferred_username}" {
		t.Fatalf("resolved as it is: %s", r.body)
	}
}
