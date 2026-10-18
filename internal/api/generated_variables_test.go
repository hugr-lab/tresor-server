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

// variable://<name> names one variable exactly; variable:// all of them; a value inside a string; a row from
// before (not dynamic) served as stored; a generated value over 64 KiB refused
func TestGeneratedVariableBounds(t *testing.T) {
	f := newFixture(t, "")
	srv, _ := sessionService(t)
	withLoginHosts(f, srv)
	login := func(name string, scope ...string) {
		quoted := `"` + srv.URL + `"`
		for _, s := range scope {
			quoted += `,"` + s + `"`
		}
		body := strings.Replace(loginBody(srv.URL, "svc", "pw-svc", ""), `"scope":["`+srv.URL+`"]`, `"scope":[`+quoted+`]`, 1)
		if r := f.do("PUT", "/v1/secrets/"+name, f.admin, body); r.status != 201 {
			t.Fatalf("login %s: %d %s", name, r.status, r.body)
		}
		f.do("PUT", "/v1/secrets/"+name+"/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	}
	login("one", "variable://tok")
	login("all", "variable://")
	get := func(name, value string) reply {
		f.do("PUT", "/v1/variables/"+name, f.admin, `{"value":`+value+`}`)
		f.do("PUT", "/v1/variables/"+name+"/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
		return f.do("GET", "/v1/variables/"+name, f.alice, "")
	}
	if r := get("tok", `"mint+login://one#session_id"`); r.status != 200 {
		t.Fatalf("named exactly: %d %s", r.status, r.body)
	}
	if r := get("tok%3Fx", `"mint+login://one#session_id"`); r.status != 403 {
		t.Fatalf("a name under it is not it: %d %s", r.status, r.body)
	}
	if r := get("anything", `"Session ${login://all#session_id}"`); r.status != 200 || r.json(t)["value"] != "Session sess-svc" {
		t.Fatalf("variable:// for all, inside a string: %d %s", r.status, r.body)
	}
	if r := get("hdr", `"Bearer ${exchange://echo-api}"`); r.status != 200 || !strings.HasPrefix(r.json(t)["value"].(string), "Bearer ey") {
		t.Fatalf("an exchange inside a string: %d %s", r.status, r.body)
	}
	// a row from before 0.6: not dynamic, a generator in it served as it was written
	stored(t, f.srv.store.Variables(), "old", `{"value":"mint+claim://preferred_username"}`)
	f.do("PUT", "/v1/variables/old/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	if r := f.do("GET", "/v1/variables/old", f.alice, ""); r.json(t)["value"] != "mint+claim://preferred_username" || r.json(t)["sensitive"] != false {
		t.Fatalf("a row from before: %s", r.body)
	}
	long := strings.Repeat("x", maxVariableBytes-100) // a token is longer than its generator
	if r := get("long", `"`+long+`${exchange://echo-api}"`); r.status != 403 {
		t.Fatalf("over 64 KiB once made: %d %s", r.status, r.body)
	}
}
