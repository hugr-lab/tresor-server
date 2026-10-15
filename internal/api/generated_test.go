package api

import (
	"context"
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
		"a rule, no field":   `{"bearer_token":"mint+rule://crm"}`,
		"a login's renewal":  `{"bearer_token":"mint+login://crm#refresh_token"}`,
		"a login, no field":  `{"bearer_token":"mint+login://crm"}`,
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

// typed values: STRUCT and LIST read, every digit kept, an untouched value served as stored, a BLOB never read
func TestGeneratedTypedValues(t *testing.T) {
	f := newFixture(t, "")
	r := f.do("PUT", "/v1/secrets/t", f.admin, `{"type":"http","provider":"config","params":{
		"s":{"type":"STRUCT(a VARCHAR, n DOUBLE)","value":{"a":"${claim://preferred_username}","n":12345678901234567890.123}},
		"l":{"type":"VARCHAR[]","value":["x","mint+claim://preferred_username"]},
		"b":{"type":"BLOB","value":"mint+claim://preferred_username"},
		"m":{"type":"MAP(VARCHAR, VARCHAR)","value":{"k":"v"}}}}`)
	if r.status != 201 || r.json(t)["dynamic"] != true {
		t.Fatalf("written: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/t/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	r = f.do("GET", "/v1/secrets/t", f.alice, "")
	for _, want := range []string{`"a":"alice"`, `12345678901234567890.123`, `["x","alice"]`,
		`"b":{"type":"BLOB","value":"mint+claim://preferred_username"}`, `"m":{"type":"MAP(VARCHAR, VARCHAR)","value":{"k":"v"}}`} {
		if !strings.Contains(string(r.body), want) {
			t.Fatalf("%s not in %s", want, r.body)
		}
	}
	redact := r.json(t)["redact_keys"].([]any)
	if len(redact) != 2 || redact[0] != "l" || redact[1] != "s" {
		t.Fatalf("redact_keys: %v", redact)
	}
	// an exchange for this service's own audience, inside a MAP: refused
	if r := f.do("PUT", "/v1/secrets/own", f.admin, `{"type":"http","provider":"config","params":{
		"h":{"type":"MAP(VARCHAR, VARCHAR)","value":{"A":"Bearer ${exchange://duckdb-secrets}"}}}}`); r.status != 422 {
		t.Fatalf("own audience in a MAP: %d %s", r.status, r.body)
	}
}

// a row written before 0.5 (not marked dynamic) makes nothing: a generator in it is a literal, so a secret said
// static is never one made per caller
func TestGeneratedStaticRow(t *testing.T) {
	f := newFixture(t, "")
	stored(t, f.srv.store, "old", `{"password":"mint+claim://preferred_username","user":"mint+bad","x":"$${y}"}`)
	f.do("PUT", "/v1/secrets/old/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	r := f.do("GET", "/v1/secrets/old", f.alice, "")
	body := r.json(t)
	params := body["params"].(map[string]any)
	if r.status != 200 || body["dynamic"] != false || body["expires_at"] != nil ||
		params["password"] != "mint+claim://preferred_username" || params["user"] != "mint+bad" || params["x"] != "${y}" {
		t.Fatalf("served as stored: %d %s", r.status, r.body)
	}
}

// the admin API's params change sets and clears the marker; a PUT without a generator makes it static
func TestGeneratedMarkerFollowsWrites(t *testing.T) {
	f := newFixture(t, "")
	withConsole(f)
	f.do("PUT", "/v1/secrets/pg", f.admin, `{"type":"postgres","provider":"config","params":{"host":"db","password":"p"}}`)
	r := f.do("PATCH", "/admin/v1/secrets/pg/params", f.admin, `{"keep":["host"],"set":{"password":"mint+claim://preferred_username"}}`,
		"If-Match", `"1"`)
	if r.status != 200 {
		t.Fatalf("patch: %d %s", r.status, r.body)
	}
	if sec, _ := f.srv.store.Get(context.Background(), "pg"); !sec.Dynamic {
		t.Fatal("a generator set: dynamic")
	}
	f.do("PATCH", "/admin/v1/secrets/pg/params", f.admin, `{"keep":["host"],"set":{"password":"p"}}`, "If-Match", `"2"`)
	if sec, _ := f.srv.store.Get(context.Background(), "pg"); sec.Dynamic {
		t.Fatal("no generator left: static")
	}
	f.do("PUT", "/v1/secrets/pg", f.admin, `{"type":"postgres","provider":"config","params":{"password":"mint+claim://sub"}}`)
	f.do("PUT", "/v1/secrets/pg", f.admin, `{"type":"postgres","provider":"config","params":{"password":"p"}}`)
	if sec, _ := f.srv.store.Get(context.Background(), "pg"); sec.Dynamic {
		t.Fatal("replaced without a generator: static")
	}
}

// under a grant: an exchange generator minted at the exchange, the user's; only the claims a usable secret
// names are kept with the grant; a claim with a control character is never kept
func TestGeneratedUnderGrant(t *testing.T) {
	f := newFixture(t, "")
	node := f.idp.Service(t, "duckdb-secrets", "node", "nodes")
	f.do("PUT", "/v1/secrets/echo", f.admin, `{"type":"http","provider":"config","params":{
		"bearer_token":"mint+exchange://echo-api","extra_http_headers":{"type":"MAP(VARCHAR, VARCHAR)","value":{"X-User":"${claim://preferred_username}"}}}}`)
	f.do("PUT", "/v1/secrets/echo/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	g, r := f.grantFor(node, f.alice)
	if g == "" || f.idp.Exchanges != 1 {
		t.Fatalf("exchange: %d %s, %d exchanges", r.status, r.body, f.idp.Exchanges)
	}
	bearer, body, r := f.mintedMaterial(node, "Delegation", g)
	if c := claimsOf(t, bearer); c["sub"] != "alice-id" || c["aud"] != "echo-api" || f.idp.Exchanges != 1 {
		t.Fatalf("alice's token, minted at the exchange: %v (%d) %s", c, f.idp.Exchanges, r.body)
	}
	if !strings.Contains(string(r.body), `"X-User":"alice"`) || body["dynamic"] != true {
		t.Fatalf("alice's claim: %s", r.body)
	}
	// a secret granted since names a claim the grant did not keep
	f.do("PUT", "/v1/secrets/azp", f.admin, `{"type":"http","provider":"config","params":{"bearer_token":"mint+claim://azp"}}`)
	f.do("PUT", "/v1/secrets/azp/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	if r := f.do("GET", "/v1/secrets/azp", node, "", "Delegation", g); r.status != 403 || !strings.Contains(string(r.body), "new session") {
		t.Fatalf("a claim not kept: %d %s", r.status, r.body)
	}
	// a claim with a line break is never kept
	mallory := f.idp.Token(t, testidp.Claims{"sub": "m-id", "aud": []string{"duckdb-secrets"},
		"realm_access": map[string]any{"roles": []any{"analysts"}}, "preferred_username": "m\r\nX-Admin: 1"})
	f.do("PUT", "/v1/secrets/echo/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	f.do("PUT", "/v1/secrets/who", f.admin, claimSecret)
	f.do("PUT", "/v1/secrets/who/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	if r := f.do("GET", "/v1/secrets/who", mallory, ""); r.status != 403 {
		t.Fatalf("a claim with a control character: %d %s", r.status, r.body)
	}
}

// the margin: a set one, and one clamped to half of a short life
func TestGeneratedMargin(t *testing.T) {
	f := newFixture(t, "")
	now := time.Now()
	f.srv.now = func() time.Time { return now }
	f.srv.cfg.Dynamic.Margin = time.Minute
	if got := f.srv.expiresAt(now.Add(time.Hour)); !got.Equal(now.Add(59 * time.Minute)) {
		t.Fatalf("a set margin: %v", got.Sub(now))
	}
	f.srv.cfg.Dynamic.Margin = 0 // the default, 10m, at most half of what is left
	if got := f.srv.expiresAt(now.Add(4 * time.Minute)); !got.Equal(now.Add(2 * time.Minute)) {
		t.Fatalf("a short life: %v", got.Sub(now))
	}
	if got := f.srv.expiresAt(now.Add(-time.Second)); got.After(now) {
		t.Fatalf("an expired value: %v", got.Sub(now))
	}
}
