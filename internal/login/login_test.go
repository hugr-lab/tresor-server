package login

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// a service with its own /login (a session id in a header) and /refresh, and an OAuth2 token endpoint
func service(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	logins := 0
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["login"] != "svc" || body["pass"] != "hunter2" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		logins++
		w.Header().Set("X-Session-Id", "sess-1")
		http.SetCookie(w, &http.Cookie{Name: "SID", Value: "cookie-1"})
		_ = json.NewEncoder(w).Encode(map[string]any{"refresh": "r-1", "ttl": 1800})
	})
	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["refresh"] != "r-1" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-Session-Id", "sess-2")
		_ = json.NewEncoder(w).Encode(map[string]any{"refresh": "r-2", "ttl": 1800})
	})
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		id, secret, _ := r.BasicAuth()
		switch {
		case r.Form.Get("grant_type") == "client_credentials" && id == "app" && secret == "s3cret":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-cc", "expires_in": 300, "token_type": "Bearer"})
		case r.Form.Get("grant_type") == "password" && r.Form.Get("username") == "u" && r.Form.Get("password") == "p":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-pw", "refresh_token": "rt", "expires_in": 300})
		case r.Form.Get("grant_type") == "refresh_token" && r.Form.Get("refresh_token") == "rt":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-renewed", "expires_in": 300})
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		}
	})
	mux.HandleFunc("POST /redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/steal", http.StatusFound)
	})
	mux.HandleFunc("POST /big", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxBody+10)))
	})
	mux.HandleFunc("POST /down", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &logins
}

func client(srv *httptest.Server) *Client {
	u, _ := url.Parse(srv.URL)
	return &Client{Hosts: []string{u.Hostname()}, Now: time.Now}
}

func TestCustomLoginAndRefresh(t *testing.T) {
	srv, logins := service(t)
	spec, err := Parse(map[string]string{"flow": "custom", "username": "svc", "password": "hunter2",
		"login_url": "/login", "login_request": `{login: $username, pass: $password}`,
		"login_response": `{session_id: .headers["x-session-id"], cookie: .cookies.SID, refresh_token: .body.refresh, expires_in: .body.ttl}`,
		"refresh_url":    "/refresh", "refresh_request": `{refresh: $refresh_token}`,
		"refresh_response": `{session_id: .headers["x-session-id"], refresh_token: .body.refresh, expires_in: .body.ttl}`},
		[]string{srv.URL + "/api"})
	if err != nil {
		t.Fatal(err)
	}
	c := client(srv)
	res, kept, err := c.Login(context.Background(), spec)
	if err != nil || res.Fields["session_id"] != "sess-1" || res.Fields["cookie"] != "cookie-1" || *logins != 1 {
		t.Fatalf("login: %+v %v", res, err)
	}
	if _, served := res.Fields["refresh_token"]; served || kept["refresh_token"] != "r-1" {
		t.Fatal("the refresh token is kept, never served")
	}
	if left := time.Until(res.Expiry); left < 29*time.Minute || left > 31*time.Minute {
		t.Fatalf("expiry from expires_in: %v", left)
	}
	res, _, ok, err := c.Refresh(context.Background(), spec, kept)
	if !ok || err != nil || res.Fields["session_id"] != "sess-2" || *logins != 1 {
		t.Fatalf("refresh: %+v %v %v", res, ok, err)
	}
	// a wrong password: refused, the value never in the error
	spec.Password = "wrong-password"
	_, _, err = c.Login(context.Background(), spec)
	var le *Error
	if !errors.As(err, &le) || !le.Refused || strings.Contains(err.Error(), "wrong-password") {
		t.Fatalf("refused: %v", err)
	}
}

func TestOAuth2Flows(t *testing.T) {
	srv, _ := service(t)
	c := client(srv)
	cc, err := Parse(map[string]string{"flow": FlowClientCredentials, "token_url": "/oauth/token",
		"client_id": "app", "client_secret": "s3cret"}, []string{srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	res, _, err := c.Login(context.Background(), cc)
	if err != nil || res.Fields["access_token"] != "at-cc" || res.Fields["token_type"] != "Bearer" {
		t.Fatalf("client credentials: %+v %v", res, err)
	}
	pw, _ := Parse(map[string]string{"flow": FlowPassword, "token_url": "/oauth/token", "username": "u",
		"password": "p", "client_id": "app"}, []string{srv.URL})
	res, kept, err := c.Login(context.Background(), pw)
	if err != nil || res.Fields["access_token"] != "at-pw" || kept["refresh_token"] != "rt" {
		t.Fatalf("password: %+v %v", res, err)
	}
	res, _, ok, err := c.Refresh(context.Background(), pw, kept)
	if !ok || err != nil || res.Fields["access_token"] != "at-renewed" {
		t.Fatalf("refresh: %+v %v", res, err)
	}
	basic, _ := Parse(map[string]string{"flow": FlowBasic, "username": "u", "password": "p"}, []string{srv.URL})
	res, _, err = c.Login(context.Background(), basic)
	if err != nil || res.Fields["authorization"] != "Basic dTpw" {
		t.Fatalf("basic: %+v %v", res, err)
	}
}

func TestBounds(t *testing.T) {
	srv, _ := service(t)
	c := client(srv)
	call := func(path string) error {
		spec, err := Parse(map[string]string{"flow": "custom", "login_url": path, "login_response": `{x: 1}`},
			[]string{srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = c.Login(context.Background(), spec)
		return err
	}
	var le *Error
	if err := call("/redirect"); !errors.As(err, &le) || !le.Refused {
		t.Fatalf("a redirect is not followed: %v", err)
	}
	if err := call("/big"); !errors.As(err, &le) || le.Refused {
		t.Fatalf("more than 1 MiB: %v", err)
	}
	if err := call("/down"); !errors.As(err, &le) || le.Refused {
		t.Fatalf("a 502 is an outage: %v", err)
	}
	spec, _ := Parse(map[string]string{"flow": "custom", "login_url": "/x", "login_response": `{x: 1}`}, []string{srv.URL})
	for _, u := range []string{"https://elsewhere.example/x", "http://example.com/x", srv.URL + "/../x"} {
		if _, err := c.CheckURL(spec, u); err == nil && !strings.HasPrefix(u, srv.URL) {
			t.Errorf("%s: allowed", u)
		}
	}
	other := &Client{Hosts: []string{"crm.example"}, Now: time.Now}
	if _, err := other.CheckURL(spec, "/x"); err == nil {
		t.Fatal("a host not in login_hosts")
	}
	if (&Client{Hosts: []string{"*.corp.example"}}).allowed("api.corp.example") != true ||
		(&Client{Hosts: []string{"*.corp.example"}}).allowed("corp.example.evil") {
		t.Fatal("a wildcard host")
	}
	// a jq that runs forever is stopped
	slow, _ := Parse(map[string]string{"flow": "custom", "login_url": "/api/login",
		"login_request": `[range(1e9)] | length`, "login_response": `{x: 1}`}, []string{srv.URL})
	start := time.Now()
	if _, _, err := c.Login(context.Background(), slow); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("a slow jq: %v after %v", err, time.Since(start))
	}
}

func TestParseRefusals(t *testing.T) {
	scope := []string{"https://crm.example"}
	for name, params := range map[string]map[string]string{
		"no flow":            {},
		"an unknown flow":    {"flow": "magic"},
		"an unknown param":   {"flow": "basic", "username": "u", "password": "p", "extra": "x"},
		"basic, no password": {"flow": "basic", "username": "u"},
		"cc, no secret":      {"flow": FlowClientCredentials, "token_url": "/t", "client_id": "a"},
		"custom, no mapping": {"flow": "custom", "login_url": "/l"},
		"a bad jq":           {"flow": "custom", "login_url": "/l", "login_response": "{"},
		"a half refresh":     {"flow": "custom", "login_url": "/l", "login_response": "{}", "refresh_url": "/r"},
		"a bad subject":      {"flow": "basic", "username": "u", "password": "p", "subject": "alice"},
		"a bad ttl":          {"flow": "basic", "username": "u", "password": "p", "ttl": "forever"},
	} {
		if _, err := Parse(params, scope); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse(map[string]string{"flow": "basic", "username": "u", "password": "p"}, nil); err == nil {
		t.Error("no scope: accepted")
	}
	s, _ := Parse(map[string]string{"flow": "basic", "username": "u", "password": "p"}, scope)
	if !s.Covers([]string{"https://crm.example/api"}) || s.Covers([]string{"https://crm.example.evil"}) || s.Covers(nil) {
		t.Fatal("covers")
	}
}

// expiry within bounds: a past, a zero, a huge one, milliseconds
func TestExpiryBounds(t *testing.T) {
	now := time.Now()
	c := &Client{Now: func() time.Time { return now }}
	s := &Spec{}
	for name, fields := range map[string]map[string]string{
		"past":         {"expires_at": now.Add(-time.Hour).Format(time.RFC3339)},
		"zero":         {"expires_in": "0"},
		"negative":     {"expires_in": "-5"},
		"huge":         {"expires_in": "1e30"},
		"milliseconds": {"expires_at": strconv.FormatInt(now.Add(time.Hour).UnixMilli(), 10)},
	} {
		res, _, _ := c.result(s, fields)
		if res.Expiry.Before(now.Add(minLife)) || res.Expiry.After(now.Add(maxLife)) {
			t.Errorf("%s: %v", name, res.Expiry.Sub(now))
		}
	}
	res, _, _ := c.result(s, map[string]string{"expires_at": strconv.FormatInt(now.Add(time.Hour).UnixMilli(), 10)})
	if d := res.Expiry.Sub(now); d < 59*time.Minute || d > 61*time.Minute {
		t.Fatalf("milliseconds read as such: %v", d)
	}
}

// a response mapping never reads the inputs; dot segments never pass a scope; a basic username with a colon
func TestInputsAndPaths(t *testing.T) {
	srv, _ := service(t)
	c := client(srv)
	spec, _ := Parse(map[string]string{"flow": "custom", "username": "svc", "password": "hunter2",
		"login_url": "/api/login", "login_request": `{login: $username, pass: $password}`,
		"login_response": `{leak: $password, session_id: .headers["x-session-id"]}`}, []string{srv.URL})
	res, _, err := c.Login(context.Background(), spec)
	if err != nil || res.Fields["leak"] == "hunter2" || res.Fields["session_id"] != "sess-1" {
		t.Fatalf("the response mapping reads no input: %+v %v", res, err)
	}
	scoped, _ := Parse(map[string]string{"flow": "basic", "username": "u", "password": "p"}, []string{srv.URL + "/tenant-a"})
	for _, u := range []string{srv.URL + "/tenant-a/../tenant-b/token", srv.URL + "/tenant-a/%2e%2e/x",
		srv.URL + "/tenant-a/a%2Fb", srv.URL + "/tenant-a/./x"} {
		if _, err := c.CheckURL(scoped, u); err == nil {
			t.Errorf("%s: within the scope", u)
		}
	}
	if scoped.Covers([]string{srv.URL + "/tenant-a/../tenant-b"}) {
		t.Error("covers a climbing scope")
	}
	colon, _ := Parse(map[string]string{"flow": "basic", "username": "a:b", "password": "p"}, []string{srv.URL})
	if _, _, err := c.Login(context.Background(), colon); err == nil {
		t.Error("a basic username with a colon")
	}
}

type fakeID struct {
	kind  string
	check error
	res   *Result
}

func (f fakeID) Kind() string                                 { return f.kind }
func (f fakeID) Check(*Spec) error                            { return f.check }
func (f fakeID) ClientID() string                             { return "app" }
func (f fakeID) Make(context.Context, *Spec) (*Result, error) { return f.res, nil }
func (f fakeID) For(tokenURL string) bool                     { return strings.HasSuffix(tokenURL, "/token") }
func (f fakeID) Destinations() []string                       { return []string{"mssql://sql.example", "http://127.0.0.1"} }
func (f fakeID) Assert(_ context.Context, tokenURL string) (string, error) {
	return "signed-for-" + tokenURL, nil
}

// a rule: the identity listed, of its flow's kind, bounded by it; a jwt_assertion: the client's assertion, as
// client authentication or as the grant (ZITADEL's JWT profile); oauth2_refresh: the stored refresh token
func TestIdentityFlows(t *testing.T) {
	srv, _ := service(t)
	var form url.Values
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.Form
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-jwt", "expires_in": 300})
	})
	tok := httptest.NewServer(mux)
	t.Cleanup(tok.Close)
	c := client(srv)
	c.Identities = map[string]Identity{
		"db":    fakeID{kind: "azure", res: &Result{Fields: map[string]string{"access_token": "entra"}, Expiry: time.Now().Add(time.Hour)}},
		"wide":  fakeID{kind: "azure", check: errors.New("not for that scope")},
		"signr": fakeID{kind: "jwt"},
	}
	far, _ := Parse(map[string]string{"flow": FlowRule, "identity": "db", "scope": "x"}, []string{"mssql://elsewhere.example"})
	if c.CheckIdentity(far) == nil {
		t.Fatal("a rule whose scope is outside its identity's destinations")
	}
	rule, err := Parse(map[string]string{"flow": FlowRule, "identity": "db", "scope": "https://database.windows.net/.default"}, []string{"mssql://sql.example"})
	if err != nil {
		t.Fatal(err)
	}
	if res, _, err := c.Login(context.Background(), rule); err != nil || res.Fields["access_token"] != "entra" {
		t.Fatalf("a rule: %+v %v", res, err)
	}
	for _, id := range []string{"wide", "signr", "nobody"} {
		rule.Identity = id
		if _, _, err := c.Login(context.Background(), rule); err == nil {
			t.Errorf("identity %s: made", id)
		}
	}
	c.Hosts = append(c.Hosts, "127.0.0.1")
	jwt, _ := Parse(map[string]string{"flow": FlowJWT, "identity": "signr", "token_url": "/token", "scope": "openid"}, []string{tok.URL})
	if res, _, err := c.Login(context.Background(), jwt); err != nil || res.Fields["access_token"] != "at-jwt" ||
		form.Get("client_assertion") != "signed-for-"+tok.URL+"/token" || form.Get("grant_type") != "client_credentials" {
		t.Fatalf("private_key_jwt: %+v %v %v", res, err, form)
	}
	jwt.Grant = "jwt_bearer"
	if _, _, err := c.Login(context.Background(), jwt); err != nil || form.Get("assertion") == "" ||
		form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || form.Get("client_assertion") != "" {
		t.Fatalf("the JWT profile: %v %v", err, form)
	}
	jwt.Identity = "db"
	if _, _, err := c.Login(context.Background(), jwt); err == nil {
		t.Fatal("a jwt_assertion with a rule's identity")
	}
	jwt.Identity, jwt.TokenURL = "signr", "/other"
	if _, _, err := c.Login(context.Background(), jwt); err == nil {
		t.Fatal("an assertion for a token endpoint the identity is not for")
	}
	if _, err := Parse(map[string]string{"flow": FlowJWT, "identity": "s", "token_url": "/t", "client_id": "x"}, []string{srv.URL}); err == nil {
		t.Fatal("a param another flow takes")
	}
	refresh, _ := Parse(map[string]string{"flow": FlowRefresh, "token_url": "/oauth/token", "refresh_token": "rt",
		"client_id": "app"}, []string{srv.URL})
	if res, _, err := c.Login(context.Background(), refresh); err != nil || res.Fields["access_token"] != "at-renewed" {
		t.Fatalf("oauth2_refresh: %+v %v", res, err)
	}
	for name, params := range map[string]map[string]string{
		"a rule's endpoint elsewhere": {"flow": "basic", "username": "u", "password": "p", "endpoint": "db:5432"},
		"a refresh token elsewhere":   {"flow": "basic", "username": "u", "password": "p", "refresh_token": "x"},
		"a bad grant":                 {"flow": FlowJWT, "identity": "s", "token_url": "/t", "grant": "password"},
	} {
		if _, err := Parse(params, []string{srv.URL}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
