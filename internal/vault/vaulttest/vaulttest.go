// Package vaulttest reaches the OpenBao and HashiCorp Vault servers the tests are given (spec 007):
//
//	TRESOR_TEST_VAULT=http://127.0.0.1:18200,http://127.0.0.1:18201   TRESOR_TEST_VAULT_TOKEN=root
//
// (dev servers: CI runs both). Each test gets mounts of its own.
package vaulttest

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Server is one Vault the tests reach, with its root token.
type Server struct {
	Name, Address, Token string
}

// Servers are the configured servers; the test is skipped when there are none (failed on CI).
func Servers(t *testing.T) []Server {
	t.Helper()
	list := os.Getenv("TRESOR_TEST_VAULT")
	if list == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TRESOR_TEST_VAULT is not set on CI")
		}
		t.Skip("TRESOR_TEST_VAULT names no Vault")
	}
	var out []Server
	for _, addr := range strings.Split(list, ",") {
		s := Server{Address: addr, Token: os.Getenv("TRESOR_TEST_VAULT_TOKEN")}
		var health struct {
			Version string `json:"version"`
		}
		s.Call(t, "GET", "sys/health", nil, &health)
		s.Name = addr + " (" + health.Version + ")"
		out = append(out, s)
	}
	return out
}

// Call calls the server as root; a failure fails the test.
func (s Server) Call(t *testing.T, method, path string, body, out any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, s.Address+"/v1/"+path, r)
	req.Header.Set("X-Vault-Token", s.Token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode/100 != 2 {
		t.Fatalf("%s %s: %d %s", method, path, res.StatusCode, raw)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
}

// Mount enables an engine (transit, kv-v2) or an auth method (jwt) at a path of the test's own.
func (s Server) Mount(t *testing.T, kind string) string {
	t.Helper()
	raw := make([]byte, 4)
	_, _ = rand.Read(raw)
	path := "t" + hex.EncodeToString(raw)
	switch kind {
	case "jwt", "kubernetes":
		s.Call(t, "POST", "sys/auth/"+path, map[string]any{"type": kind}, nil)
	case "kv-v2":
		s.Call(t, "POST", "sys/mounts/"+path, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}, nil)
	default:
		s.Call(t, "POST", "sys/mounts/"+path, map[string]any{"type": kind}, nil)
	}
	return path
}

// TokenFile writes the root token to a file: the token_file login.
func (s Server) TokenFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(s.Token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
