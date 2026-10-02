package vault

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
)

// fake is a Vault of a few answers: a JWT login, a path the policy refuses, a path that redirects elsewhere
type fake struct {
	logins    atomic.Int32
	loginFail atomic.Bool
	lease     int
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/auth/jwt/login":
		if f.loginFail.Load() {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"errors":["the auth backend is down"]}`))
			return
		}
		n := f.logins.Add(1)
		_, _ = w.Write([]byte(`{"auth":{"client_token":"tok-` + string(rune('0'+n)) + `","lease_duration":` + itoa(f.lease) + `}}`))
	case "/v1/auth/token/lookup-self":
		_, _ = w.Write([]byte(`{"data":{}}`)) // every token lives
	case "/v1/forbidden":
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
	case "/v1/ok":
		_, _ = w.Write([]byte(`{"data":{}}`))
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func jwtClient(t *testing.T, url string) *Client {
	t.Helper()
	jf := filepath.Join(t.TempDir(), "jwt")
	_ = os.WriteFile(jf, []byte("a.b.c"), 0o600)
	c, err := New(Config{Address: url, Auth: Auth{Method: "jwt", Role: "r", JWTFile: jf}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// a refusal of the policy, with a live token: no login each time
func TestNoLoginStorm(t *testing.T) {
	f := &fake{lease: 3600}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := jwtClient(t, srv.URL)
	for range 10 {
		if err := c.Do(ctx, "GET", "forbidden", nil, nil); err == nil {
			t.Fatal("a refusal answered ok")
		}
	}
	if n := f.logins.Load(); n != 1 {
		t.Fatalf("%d logins for 10 refusals of the policy", n)
	}
}

// a login that fails while the old token lives: the old token serves
func TestLoginBlip(t *testing.T) {
	f := &fake{lease: 3600}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := jwtClient(t, srv.URL)
	if err := c.Do(ctx, "GET", "ok", nil, nil); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.renewAt = c.renewAt.Add(-3600e9) // past two thirds of the lease
	c.mu.Unlock()
	f.loginFail.Store(true)
	if err := c.Do(ctx, "GET", "ok", nil, nil); err != nil {
		t.Fatalf("the auth backend's blip failed a call: %v", err)
	}
}

// a redirect is answered as it is, never followed: the token and the body go nowhere else
func TestNoRedirect(t *testing.T) {
	var leaked atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "" {
			leaked.Store(true)
		}
	}))
	defer elsewhere.Close()
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer vault.Close()
	tf := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tf, []byte("SECRET-TOKEN"), 0o600)
	c, _ := New(Config{Address: vault.URL, Auth: Auth{Method: "token_file", TokenFile: tf}})
	err := c.Do(ctx, "POST", "transit/encrypt/k", map[string]string{"plaintext": "DEK"}, nil)
	if err == nil || leaked.Load() {
		t.Fatalf("a redirect followed: %v, leaked %v", err, leaked.Load())
	}
}
