package api

import (
	"strings"
	"testing"

	"github.com/hugr-lab/tresor-server/internal/auth"
	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/testidp"
)

// whoami's name (spec 030, tresor spec 041): who the subject is, for people to read - the first non-blank of
// preferred_username, name, email; under a delegation grant the grant's user's; absent when the token has none
func TestWhoamiName(t *testing.T) {
	f := newFixture(t, "")
	if r := f.do("GET", "/v1/whoami", f.alice, ""); r.json(t)["name"] != "alice" {
		t.Fatalf("alice: %s", r.body)
	}
	byEmail := f.idp.Token(t, testidp.Claims{"sub": "e-id", "aud": []string{"duckdb-secrets"},
		"preferred_username": "  ", "email": "e@example.com"})
	if r := f.do("GET", "/v1/whoami", byEmail, ""); r.json(t)["name"] != "e@example.com" {
		t.Fatalf("by email: %s", r.body)
	}
	none := f.idp.Token(t, testidp.Claims{"sub": "n-id", "aud": []string{"duckdb-secrets"}})
	if r := f.do("GET", "/v1/whoami", none, ""); strings.Contains(string(r.body), `"name"`) {
		t.Fatalf("no name: %s", r.body)
	}
	node := f.idp.Service(t, "duckdb-secrets", "node", "nodes")
	g, gr := f.grantFor(node, f.alice)
	if g == "" {
		t.Fatalf("exchange: %d %s", gr.status, gr.body)
	}
	if r := f.do("GET", "/v1/whoami", node, "", "Delegation", g); r.json(t)["name"] != "alice" {
		t.Fatalf("under the grant, the user's: %s", r.body)
	}
}

// an issuer's ignore_roles: an IdP's own roles never become principals
func TestIgnoreRoles(t *testing.T) {
	f := newFixture(t, "")
	issuers := append([]config.Issuer(nil), f.srv.cfg.Issuers...)
	issuers[0].IgnoreRoles = []string{"offline_access", "default-roles-*"}
	f.srv.verifier = auth.NewVerifier(issuers)
	tok := f.idp.Person(t, "duckdb-secrets", "analysts", "offline_access", "default-roles-tresor")
	r := f.do("GET", "/v1/whoami", tok, "")
	roles := r.json(t)["roles"].([]any)
	if len(roles) != 1 || roles[0] != "role:analysts" {
		t.Fatalf("roles: %v", roles)
	}
}
