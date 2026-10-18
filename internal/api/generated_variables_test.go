package api

import (
	"strings"
	"testing"
	"time"
)

// a variable's value made on each read, as a secret's parameter (spec 024): a claim, an exchange, a part of the
// string; sensitive, with expires_at; in a list sensitive too; a static one as it is
func TestGeneratedVariables(t *testing.T) {
	f := newFixture(t, "")
	put := func(name, value string) reply {
		return f.do("PUT", "/v1/variables/"+name, f.admin, `{"value":`+value+`}`)
	}
	if r := put("who", `"user=${claim://preferred_username}"`); r.status != 201 {
		t.Fatalf("a claim: %d %s", r.status, r.body)
	}
	if r := put("tok", `"mint+exchange://echo-api"`); r.status != 201 {
		t.Fatalf("an exchange: %d %s", r.status, r.body)
	}
	put("plain", `"s3://lake"`)
	for _, bad := range []string{`"mint+claim://sid"`, `"mint+exchange://duckdb-secrets"`, `"mint+nothing://x"`} {
		if r := put("bad", bad); r.status != 422 {
			t.Errorf("%s: %d %s", bad, r.status, r.body)
		}
	}
	for _, n := range []string{"who", "tok", "plain"} {
		f.do("PUT", "/v1/variables/"+n+"/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	}
	r := f.do("GET", "/v1/variables/who", f.alice, "")
	body := r.json(t)
	if r.status != 200 || body["value"] != "user=alice" || body["sensitive"] != true {
		t.Fatalf("a claim's value: %d %s", r.status, r.body)
	}
	if exp, err := time.Parse(time.RFC3339, body["expires_at"].(string)); err != nil || !exp.After(time.Now()) {
		t.Fatalf("expires_at: %v", body["expires_at"])
	}
	r = f.do("GET", "/v1/variables/tok", f.alice, "")
	if c := claimsOf(t, r.json(t)["value"].(string)); r.status != 200 || c["sub"] != "alice-id" || c["aud"] != "echo-api" {
		t.Fatalf("a token for alice: %d %s", r.status, r.body)
	}
	if strings.Contains(f.logs.String(), r.json(t)["value"].(string)) {
		t.Fatal("a token reached the log")
	}
	r = f.do("GET", "/v1/variables/plain", f.alice, "")
	if body := r.json(t); body["value"] != "s3://lake" || body["sensitive"] != false || body["expires_at"] != nil {
		t.Fatalf("a static variable: %s", r.body)
	}
	list := f.do("GET", "/v1/variables", f.alice, "")
	if !strings.Contains(string(list.body), `"name":"who"`) || strings.Count(string(list.body), `"sensitive":true`) != 2 {
		t.Fatalf("listed sensitive: %s", list.body)
	}
	// under a delegation grant, the grant's user's
	node := f.idp.Service(t, "duckdb-secrets", "node", "nodes")
	f.do("PUT", "/v1/variables/who/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	g, gr := f.grantFor(node, f.alice)
	if g == "" {
		t.Fatalf("exchange: %d %s", gr.status, gr.body)
	}
	if r := f.do("GET", "/v1/variables/who", node, "", "Delegation", g); r.json(t)["value"] != "user=alice" {
		t.Fatalf("the grant's user's: %s", r.body)
	}
}

// a login's field reaches a variable only when the login's scope names it (variable://<name>)
func TestGeneratedVariableFromLogin(t *testing.T) {
	f := newFixture(t, "")
	srv, _ := sessionService(t)
	withLoginHosts(f, srv)
	body := strings.Replace(loginBody(srv.URL, "svc", "pw-svc", ""), `"scope":["`+srv.URL+`"]`,
		`"scope":["`+srv.URL+`","variable://session"]`, 1)
	if r := f.do("PUT", "/v1/secrets/crm", f.admin, body); r.status != 201 {
		t.Fatalf("a login: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/crm/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	for _, n := range []string{"session", "other"} {
		f.do("PUT", "/v1/variables/"+n, f.admin, `{"value":"mint+login://crm#session_id"}`)
		f.do("PUT", "/v1/variables/"+n+"/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	}
	if r := f.do("GET", "/v1/variables/session", f.alice, ""); r.status != 200 || r.json(t)["value"] != "sess-svc" {
		t.Fatalf("named by the login: %d %s", r.status, r.body)
	}
	if r := f.do("GET", "/v1/variables/other", f.alice, ""); r.status != 403 {
		t.Fatalf("not named by the login: %d %s", r.status, r.body)
	}
}
