package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

// the page at any route of the app, the config for the sign-in, the headers on everything
func TestHandler(t *testing.T) {
	h := Handler(Config{BasePath: "/secrets", API: "https://svc.example/secrets", Environment: "prod",
		Issuers: []Issuer{{Issuer: "https://idp.example/realms/main", ClientID: "duckdb", Audience: "duckdb-secrets"}}})
	for _, p := range []string{"/ui/", "/ui/secrets/lake_s3", "/ui/variables"} {
		w := get(t, h, p)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `<base href="/secrets/ui/">`) {
			t.Fatalf("%s: %d %s", p, w.Code, w.Body.String())
		}
		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "connect-src 'self' https://idp.example") || !strings.Contains(csp, "frame-ancestors 'none'") ||
			strings.Contains(csp, "unsafe") {
			t.Fatalf("%s: CSP %q", p, csp)
		}
		if w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: headers %v", p, w.Header())
		}
	}
	w := get(t, h, "/ui/config.json")
	var cfg map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil || cfg["environment"] != "prod" ||
		cfg["issuers"].([]any)[0].(map[string]any)["client_id"] != "duckdb" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("config: %s %v", w.Body.String(), err)
	}
	if w := get(t, h, "/ui/assets/missing.js"); w.Code != 404 {
		t.Fatalf("a missing asset: %d", w.Code)
	}
	if w := get(t, h, "/ui"); w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "/secrets/ui/" {
		t.Fatalf("/ui: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := get(t, h, "/ui/../../etc/passwd"); w.Code == 200 && !strings.Contains(w.Body.String(), "<base") {
		t.Fatal("a path out of the build")
	}
	framed := Handler(Config{FrameAncestors: []string{"https://platform.example"}})
	if csp := get(t, framed, "/ui/").Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors https://platform.example") {
		t.Fatal(csp)
	}
	post := httptest.NewRecorder()
	h.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/ui/config.json", nil))
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", post.Code)
	}
}
