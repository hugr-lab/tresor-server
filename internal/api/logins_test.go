package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hugr-lab/tresor-server/internal/testidp"
)

// a service with its own login: a user and a password give a session id, in a header
func sessionService(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var logins atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.URL.Path != "/login" || body["pass"] != "pw-"+body["user"] {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		logins.Add(1)
		w.Header().Set("X-Session-Id", "sess-"+body["user"])
		_, _ = w.Write([]byte(`{"ttl":1800}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &logins
}

func loginBody(scope, user, pass, subject string) string {
	params := map[string]any{"flow": "custom", "username": user, "password": pass, "login_url": "/login",
		"login_request":  `{user: $username, pass: $password}`,
		"login_response": `{session_id: .headers["x-session-id"], expires_in: .body.ttl}`}
	if subject != "" {
		params["subject"] = subject
	}
	b, _ := json.Marshal(map[string]any{"type": "tresor_service_login", "provider": "config", "scope": []string{scope},
		"params": params})
	return string(b)
}

func withLoginHosts(f *fixture, srv *httptest.Server) {
	u, _ := url.Parse(srv.URL)
	f.srv.cfg.Dynamic.LoginHosts = []string{u.Hostname()}
}

// a named login: its session id served in a secret, the login never served itself
func TestServiceLogin(t *testing.T) {
	f := newFixture(t, "")
	withConsole(f)
	srv, logins := sessionService(t)
	if r := f.do("PUT", "/v1/secrets/crm", f.admin, loginBody(srv.URL, "svc", "pw-svc", "")); r.status != 422 {
		t.Fatalf("a host not allowed: %d %s", r.status, r.body)
	}
	withLoginHosts(f, srv)
	if r := f.do("PUT", "/v1/secrets/crm", f.admin, loginBody(srv.URL, "svc", "pw-svc", "")); r.status != 201 {
		t.Fatalf("a login: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/crm/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	r := f.do("PUT", "/v1/secrets/data", f.admin, `{"type":"http","provider":"config","scope":["`+srv.URL+`/data"],
		"params":{"extra_http_headers":{"type":"MAP(VARCHAR, VARCHAR)","value":{"X-Session":"${login://crm#session_id}"}},
		"bearer_token":"mint+login://crm#session_id"}}`)
	if r.status != 201 || r.json(t)["dynamic"] != true {
		t.Fatalf("a secret of the login: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/data/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	r = f.do("GET", "/v1/secrets/data", f.alice, "")
	body := r.json(t)
	params := body["params"].(map[string]any)
	if r.status != 200 || params["bearer_token"] != "sess-svc" ||
		params["extra_http_headers"].(map[string]any)["value"].(map[string]any)["X-Session"] != "sess-svc" {
		t.Fatalf("material: %d %s", r.status, r.body)
	}
	f.do("GET", "/v1/secrets/data", f.alice, "")
	if logins.Load() != 1 {
		t.Fatalf("cached: %d logins", logins.Load())
	}
	// never served: not listed, not read - the console lists them
	if list := f.do("GET", "/v1/secrets", f.admin, ""); strings.Contains(string(list.body), `"crm"`) {
		t.Fatalf("listed: %s", list.body)
	}
	if r := f.do("GET", "/v1/secrets/crm", f.alice, ""); r.status != 404 || strings.Contains(string(r.body), "pw-svc") {
		t.Fatalf("read: %d %s", r.status, r.body)
	}
	if r := f.do("GET", "/admin/v1/logins", f.admin, ""); !strings.Contains(string(r.body), `"crm"`) {
		t.Fatalf("the console's list: %d %s", r.status, r.body)
	}
	if strings.Contains(f.logs.String(), "sess-svc") || strings.Contains(f.logs.String(), "pw-svc") {
		t.Fatal("a session or a password reached the log")
	}
	// a secret outside the login's scope, and a caller who may not use the login: refused
	f.do("PUT", "/v1/secrets/far", f.admin, `{"type":"http","provider":"config","scope":["https://elsewhere.example"],
		"params":{"bearer_token":"mint+login://crm#session_id"}}`)
	f.do("PUT", "/v1/secrets/far/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	if r := f.do("GET", "/v1/secrets/far", f.alice, ""); r.status != 403 {
		t.Fatalf("outside the scope: %d %s", r.status, r.body)
	}
	f.do("DELETE", "/v1/secrets/crm/grants/a", f.admin, "")
	if r := f.do("GET", "/v1/secrets/data", f.alice, ""); r.status != 403 {
		t.Fatalf("no use of the login: %d %s", r.status, r.body)
	}
	// a login takes claims only: no exchange in it
	bad := strings.Replace(loginBody(srv.URL, "svc", "pw-svc", ""), `"svc"`, `"${exchange://echo-api}"`, 1)
	if r := f.do("PUT", "/v1/secrets/bad", f.admin, bad); r.status != 422 {
		t.Fatalf("an exchange in a login: %d %s", r.status, r.body)
	}
}

// per user: logins bound to their users, picked by the secret's scope for the effective user - under a
// delegation grant the grant's user, never the server; no login of one's own, refused
func TestServiceLoginPerUser(t *testing.T) {
	f := newFixture(t, "")
	srv, _ := sessionService(t)
	withLoginHosts(f, srv)
	alice := "subject:" + f.idp.URL + "|alice-id"
	bob := f.idp.Token(t, testidp.Claims{"sub": "bob-id", "aud": []string{"duckdb-secrets"},
		"realm_access": map[string]any{"roles": []any{"analysts"}}})
	for name, body := range map[string]string{
		"crm-alice": loginBody(srv.URL, "alice", "pw-alice", alice),
		"crm-bob":   loginBody(srv.URL, "bob", "pw-bob", "subject:"+f.idp.URL+"|bob-id"),
	} {
		if r := f.do("PUT", "/v1/secrets/"+name, f.admin, body); r.status != 201 {
			t.Fatalf("%s: %d %s", name, r.status, r.body)
		}
		f.do("PUT", "/v1/secrets/"+name+"/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
		f.do("PUT", "/v1/secrets/"+name+"/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	}
	f.do("PUT", "/v1/secrets/data", f.admin, `{"type":"http","provider":"config","scope":["`+srv.URL+`"],
		"params":{"bearer_token":"mint+login:scope#session_id"}}`)
	f.do("PUT", "/v1/secrets/data/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	f.do("PUT", "/v1/secrets/data/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	session := func(token string, headers ...string) (string, int) {
		r := f.do("GET", "/v1/secrets/data", token, "", headers...)
		if r.status != 200 {
			return "", r.status
		}
		return r.json(t)["params"].(map[string]any)["bearer_token"].(string), 200
	}
	if s, _ := session(f.alice); s != "sess-alice" {
		t.Fatalf("alice's: %q", s)
	}
	if s, _ := session(bob); s != "sess-bob" {
		t.Fatalf("bob's: %q", s)
	}
	carol := f.idp.Token(t, testidp.Claims{"sub": "carol-id", "aud": []string{"duckdb-secrets"},
		"realm_access": map[string]any{"roles": []any{"analysts"}}})
	if _, status := session(carol); status != 403 {
		t.Fatalf("no login of her own: %d", status)
	}
	node := f.idp.Service(t, "duckdb-secrets", "node", "nodes")
	g, r := f.grantFor(node, f.alice)
	if g == "" {
		t.Fatalf("exchange: %d %s", r.status, r.body)
	}
	if s, _ := session(node, "Delegation", g); s != "sess-alice" {
		t.Fatalf("under alice's grant, alice's: %q", s)
	}
	if _, status := session(node); status != 403 {
		t.Fatalf("the node as itself has no login: %d", status)
	}
}

// one login for everybody, its user from the caller's claim: per user, never shared
func TestServiceLoginFromClaims(t *testing.T) {
	f := newFixture(t, "")
	srv, logins := sessionService(t)
	withLoginHosts(f, srv)
	body := loginBody(srv.URL, "${claim://preferred_username}", "pw-${claim://preferred_username}", "")
	if r := f.do("PUT", "/v1/secrets/crm", f.admin, body); r.status != 201 {
		t.Fatalf("a login of claims: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/crm/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	f.do("PUT", "/v1/secrets/data", f.admin, `{"type":"http","provider":"config","scope":["`+srv.URL+`"],
		"params":{"bearer_token":"mint+login://crm#session_id"}}`)
	f.do("PUT", "/v1/secrets/data/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	r := f.do("GET", "/v1/secrets/data", f.alice, "")
	if r.status != 200 || r.json(t)["params"].(map[string]any)["bearer_token"] != "sess-alice" {
		t.Fatalf("alice's session: %d %s", r.status, r.body)
	}
	dave := f.idp.Token(t, testidp.Claims{"sub": "dave-id", "aud": []string{"duckdb-secrets"},
		"realm_access": map[string]any{"roles": []any{"analysts"}}, "preferred_username": "dave"})
	r = f.do("GET", "/v1/secrets/data", dave, "")
	if r.status != 200 || r.json(t)["params"].(map[string]any)["bearer_token"] != "sess-dave" || logins.Load() != 2 {
		t.Fatalf("dave's own: %d %s (%d logins)", r.status, r.body, logins.Load())
	}
}
