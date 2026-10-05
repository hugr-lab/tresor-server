package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hugr-lab/tresor-server/internal/audit"
	"github.com/hugr-lab/tresor-server/internal/auth"
	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/state"
	"github.com/hugr-lab/tresor-server/internal/state/memory"
)

// withConsole serves the console's routes on the fixture (spec 010)
func withConsole(f *fixture) {
	f.srv.console = &Console{UI: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("console"))
	}), Version: "test", KEK: func(context.Context) (string, error) { return "local:v1", nil },
		Ready: func() (bool, map[string]string) { return true, map[string]string{"state": "ready"} }}
	f.server.Config.Handler = f.srv.Handler()
}

// stored writes an entry straight to the store: a reference to no configured source, as an older
// configuration may have left one
func stored(t *testing.T, st state.Store, name string, params string, redact ...string) {
	t.Helper()
	var p map[string]json.RawMessage
	if err := json.Unmarshal([]byte(params), &p); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Update(context.Background(), name, func(*state.Secret) (*state.Secret, error) {
		return &state.Secret{Name: name, Type: "postgres", Provider: "config", Params: p, RedactKeys: redact, Version: 1}, nil
	}); err != nil {
		t.Fatal(err)
	}
}

// administrators only, calling directly; the console's page itself needs no token
func TestAdminOnly(t *testing.T) {
	f := newFixture(t, "")
	withConsole(f)
	stored(t, f.srv.store, "pg", `{"host":"db"}`)
	routes := [][2]string{{"GET", "/admin/v1/service"}, {"GET", "/admin/v1/secrets/pg/shape"},
		{"GET", "/admin/v1/grants"}, {"POST", "/admin/v1/refs-check"}, {"PATCH", "/admin/v1/secrets/pg/params"}}
	for _, rt := range routes {
		if r := f.do(rt[0], rt[1], "", "{}"); r.status != 401 {
			t.Errorf("%s with no token: %d", rt[1], r.status)
		}
		if r := f.do(rt[0], rt[1], f.alice, "{}", "If-Match", `"1"`); r.status != 403 || r.problemType(t) != "no_verb" {
			t.Errorf("%s for a user: %d %s", rt[1], r.status, r.body)
		}
		if r := f.do(rt[0], rt[1], f.admin, "{}"); r.status == 401 || r.status == 403 {
			t.Errorf("%s for an administrator: %d %s", rt[1], r.status, r.body)
		}
	}
	// an administrator through a server: never (the node may pass management on, not the console's API)
	id, rep := f.grantFor(f.idp.Service(t, "duckdb-secrets", "admin-node"), f.admin)
	if id == "" {
		t.Fatalf("a grant: %d %s", rep.status, rep.body)
	}
	if r := f.do("GET", "/admin/v1/service", f.idp.Service(t, "duckdb-secrets", "admin-node"), "", "Delegation", id); r.status != 403 ||
		r.problemType(t) != "actor_not_allowed" {
		t.Fatalf("through a server: %d %s", r.status, r.body)
	}
	if r := f.do("GET", "/ui/", "", ""); r.status != 200 || string(r.body) != "console" {
		t.Fatalf("the page: %d %s", r.status, r.body)
	}
}

// the shape: names, types, which are secret, references as written; values only when asked, and never a
// secret one or what a reference holds - every reveal audited
func TestShape(t *testing.T) {
	f := newFixture(t, "")
	withConsole(f)
	buf := audited(f, audit.Changes)
	stored(t, f.srv.store, "pg", `{"host":"db.example","port":{"type":"INTEGER","value":5432},
		"password":{"type":"VARCHAR","value":"hunter2"},"dsn":"ref+vault://secret/duckdb/pg#dsn"}`, "password", "dsn")
	shape := func(q string) map[string]map[string]any {
		r := f.do("GET", "/admin/v1/secrets/pg/shape"+q, f.admin, "")
		if r.status != 200 || strings.Contains(string(r.body), "hunter2") {
			t.Fatalf("%d %s", r.status, r.body)
		}
		out := map[string]map[string]any{}
		for _, p := range r.json(t)["params"].([]any) {
			p := p.(map[string]any)
			out[p["name"].(string)] = p
		}
		return out
	}
	plain := shape("")
	for name, p := range plain {
		if _, ok := p["value"]; ok {
			t.Fatalf("a value without values=1: %s", name)
		}
	}
	if plain["port"]["type"] != "INTEGER" || plain["password"]["redacted"] != true ||
		plain["dsn"]["reference"] != "ref+vault://secret/duckdb/pg#dsn" {
		t.Fatalf("%v", plain)
	}
	shown := shape("?values=1")
	if shown["host"]["value"] != "db.example" || shown["port"]["value"] == nil {
		t.Fatalf("plain values: %v", shown)
	}
	if _, ok := shown["password"]["value"]; ok {
		t.Fatal("a secret parameter's value")
	}
	if _, ok := shown["dsn"]["value"]; ok {
		t.Fatal("a reference's value")
	}
	es := events(t, buf)
	if find(es, audit.KindReveal, "ok", "pg") == nil || find(es, audit.KindInspect, "ok", "pg") != nil {
		t.Fatalf("a reveal is audited even at changes, an inspection is not: %v", es)
	}
	if r := f.do("GET", "/admin/v1/secrets/nope/shape", f.admin, ""); r.status != 404 {
		t.Fatalf("a missing secret: %d", r.status)
	}
	// a variable's: its value, unless it is a reference
	if r := f.do("PUT", "/v1/variables/bucket", f.admin, `{"value":"s3://lake"}`); r.status != 201 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	r := f.do("GET", "/admin/v1/variables/bucket/shape?values=1", f.admin, "")
	if r.status != 200 || !strings.Contains(string(r.body), `"value":"s3://lake"`) || r.json(t)["kind"] != "variable" {
		t.Fatalf("a variable: %d %s", r.status, r.body)
	}
}

// a replace that keeps what the administrator never saw: every parameter kept, set or removed, on the version
// the edit started from
func TestParamsMerge(t *testing.T) {
	f := newFixture(t, "")
	withConsole(f)
	stored(t, f.srv.store, "pg", `{"host":"db","password":"hunter2","sslmode":"disable"}`, "password")
	patch := func(body, version string) reply {
		h := []string{}
		if version != "" {
			h = []string{"If-Match", version}
		}
		return f.do("PATCH", "/admin/v1/secrets/pg/params", f.admin, body, h...)
	}
	for name, c := range map[string]struct {
		body, version string
		status        int
	}{
		"no If-Match":         {`{"keep":["host","password","sslmode"]}`, "", 412},
		"another version":     {`{"keep":["host","password","sslmode"]}`, `"7"`, 412},
		"a parameter omitted": {`{"keep":["host","password"]}`, `"1"`, 422},
		"kept and set":        {`{"keep":["host","password","sslmode"],"set":{"host":"x"}}`, `"1"`, 422},
		"an unknown kept":     {`{"keep":["host","password","sslmode","port"]}`, `"1"`, 422},
		"an unknown removed":  {`{"keep":["host","password","sslmode"],"remove":["port"]}`, `"1"`, 422},
		"a null value":        {`{"keep":["password","sslmode"],"set":{"host":null}}`, `"1"`, 422},
	} {
		if r := patch(c.body, c.version); r.status != c.status {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	r := patch(`{"keep":["password"],"set":{"host":"db2","port":{"type":"INTEGER","value":5433}},"remove":["sslmode"],"comment":"moved"}`, `"1"`)
	if r.status != 200 || r.header.Get("ETag") != `"2"` {
		t.Fatalf("%d %s", r.status, r.body)
	}
	sec, _ := f.srv.store.Get(context.Background(), "pg")
	if string(sec.Params["password"]) != `"hunter2"` || string(sec.Params["host"]) != `"db2"` || sec.Params["sslmode"] != nil ||
		len(sec.RedactKeys) != 1 || sec.RedactKeys[0] != "password" || sec.Comment != "moved" {
		t.Fatalf("%+v", sec)
	}
	// a reference set through it is checked as at a PUT: no source configured here
	if r := patch(`{"keep":["host","password","port"],"set":{"dsn":"ref+vault://secret/x#y"}}`, `"2"`); r.status != 422 {
		t.Fatalf("a reference to no source: %d %s", r.status, r.body)
	}
}

// grants by principal: who holds what, across secrets and variables
func TestGrantsByPrincipal(t *testing.T) {
	f := newFixture(t, "")
	withConsole(f)
	f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret)
	f.do("PUT", "/v1/variables/bucket", f.admin, `{"value":"s3://lake"}`)
	f.do("PUT", "/v1/secrets/lake/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	f.do("PUT", "/v1/secrets/lake/grants/s", f.admin, `{"principal":"group:sales","verbs":["use"]}`)
	f.do("PUT", "/v1/variables/bucket/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	r := f.do("GET", "/admin/v1/grants", f.admin, "")
	if r.status != 200 || !strings.Contains(string(r.body), `{"count":2,"principal":"role:analysts"}`) ||
		!strings.Contains(string(r.body), `{"count":1,"principal":"group:sales"}`) || strings.Contains(string(r.body), "entries") {
		t.Fatalf("%d %s", r.status, r.body)
	}
	r = f.do("GET", "/admin/v1/grants?principal=role:analysts", f.admin, "")
	entries := r.json(t)["entries"].([]any)
	if len(entries) != 2 || !strings.Contains(string(r.body), `"others":["group:sales"]`) {
		t.Fatalf("%s", r.body)
	}
}

// the references check over HTTP, and the service as it runs - no key, no token
func TestRefsCheckAndService(t *testing.T) {
	f := newFixture(t, "")
	withConsole(f)
	stored(t, f.srv.store, "pg", `{"password":"ref+vault-us://secret/x#y"}`, "password")
	r := f.do("POST", "/admin/v1/refs-check", f.admin, `{"resolve":false}`)
	body := r.json(t)
	if r.status != 200 || body["checked"].(float64) != 1 || len(body["findings"].([]any)) != 1 ||
		!strings.Contains(string(r.body), "no source for vault-us") {
		t.Fatalf("%d %s", r.status, r.body)
	}
	r = f.do("GET", "/admin/v1/service", f.admin, "")
	svc := r.json(t)
	if r.status != 200 || svc["version"] != "test" || svc["kek"].(map[string]any)["current"] != "local:v1" ||
		svc["ready"].(map[string]any)["ready"] != true || len(svc["issuers"].([]any)) != 1 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	if strings.Contains(string(r.body), "TRESOR_TEST_EXCHANGE") {
		t.Fatal("a secret's variable name in the service page")
	}
}

// CORS for the console's hosts only, never with credentials
func TestCORS(t *testing.T) {
	cfg, err := config.Parse([]byte(`
listen: 127.0.0.1:0
public_url: http://127.0.0.1:8443
state: {kind: memory}
issuers: [{issuer: 'http://127.0.0.1:18080/realms/t', audience: duckdb-secrets}]
policy: {admins: [role:secrets_admin]}
ui: {allowed_origins: ['https://platform.example']}
`))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(context.Background(), cfg, auth.NewVerifier(cfg.Issuers), memory.New(), slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithConsole(Console{UI: http.NotFoundHandler()}))
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	call := func(method, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/admin/v1/service", nil)
		req.Header.Set("Origin", origin)
		if method == "OPTIONS" {
			req.Header.Set("Access-Control-Request-Method", "GET")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	w := call("OPTIONS", "https://platform.example")
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != "https://platform.example" ||
		!strings.Contains(w.Header().Get("Access-Control-Allow-Headers"), "If-Match") ||
		w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("a preflight: %d %v", w.Code, w.Header())
	}
	if w := call("GET", "https://platform.example"); w.Code != 401 || w.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Fatalf("a call: %d %v", w.Code, w.Header())
	}
	for _, method := range []string{"OPTIONS", "GET"} {
		if w := call(method, "https://evil.example"); w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("%s from another origin: %v", method, w.Header())
		}
	}
}

// a kept parameter keeps its mark: unmarking a value the administrator never saw would reveal it; a mark goes
// only with a value set anew
func TestParamsMergeKeepsMarks(t *testing.T) {
	f := newFixture(t, "")
	withConsole(f)
	stored(t, f.srv.store, "pg", `{"host":"db","password":"hunter2"}`, "password")
	r := f.do("PATCH", "/admin/v1/secrets/pg/params", f.admin, `{"keep":["host","password"],"redact_keys":[]}`, "If-Match", `"1"`)
	if r.status != 422 || strings.Contains(string(r.body), "hunter2") {
		t.Fatalf("unmarking a kept secret: %d %s", r.status, r.body)
	}
	if r := f.do("GET", "/admin/v1/secrets/pg/shape?values=1", f.admin, ""); strings.Contains(string(r.body), "hunter2") {
		t.Fatalf("revealed: %s", r.body)
	}
	if r := f.do("PATCH", "/admin/v1/secrets/pg/params", f.admin, `{"keep":["host"],"set":{"password":"not-secret-now"},"redact_keys":[]}`, "If-Match", `"1"`); r.status != 200 {
		t.Fatalf("a new value, unmarked: %d %s", r.status, r.body)
	}
	for _, tag := range []string{"*", `W/"2"`} {
		if r := f.do("PATCH", "/admin/v1/secrets/pg/params", f.admin, `{"keep":["host","password"]}`, "If-Match", tag); r.status != 412 ||
			!strings.Contains(string(r.body), "exact version") {
			t.Fatalf("If-Match %s: %d %s", tag, r.status, r.body)
		}
	}
}

// the recorder reaches the connection: the references check's longer write deadline takes effect
func TestRecorderUnwraps(t *testing.T) {
	var got error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = http.NewResponseController(&statusRecorder{ResponseWriter: w}).SetWriteDeadline(time.Now().Add(time.Minute))
	}))
	defer srv.Close()
	res, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got != nil {
		t.Fatalf("SetWriteDeadline through the recorder: %v", got)
	}
}
