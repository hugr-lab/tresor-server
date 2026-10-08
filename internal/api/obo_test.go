package api

import (
	"strings"
	"testing"
	"time"

	"github.com/hugr-lab/tresor-server/internal/testidp"
)

// Entra's On-Behalf-Of (spec 013): the caller's token as the assertion, a scope (the audience's .default, or the
// secret's), offline_access when a grant wants a refresh token; Entra's error code kept, its message not
func TestMintedOnBehalfOf(t *testing.T) {
	f := newFixture(t, "")
	f.srv.cfg.Issuers[0].Exchange.Grant = "on_behalf_of"
	f.do("PUT", "/v1/secrets/echo", f.admin, mintedSecret)
	f.do("PUT", "/v1/secrets/echo/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	f.do("PUT", "/v1/secrets/echo/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)

	bearer, _, r := f.mintedMaterial(f.alice)
	if bearer == "" {
		t.Fatalf("minted by OBO: %d %s", r.status, r.body)
	}
	form := f.idp.LastForm
	if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || form.Get("requested_token_use") != "on_behalf_of" ||
		form.Get("assertion") != f.alice || form.Get("scope") != "echo-api/.default" || form.Get("subject_token") != "" ||
		form.Get("audience") != "" {
		t.Fatalf("the OBO request: %v", form)
	}
	if c := claimsOf(t, bearer); c["sub"] != "alice-id" || c["aud"] != "echo-api" || f.idp.OBOs != 1 || f.idp.Exchanges != 0 {
		t.Fatalf("alice's token for echo-api: %v (%d OBO, %d RFC 8693)", c, f.idp.OBOs, f.idp.Exchanges)
	}

	// under a delegation grant: offline_access, a refresh token, renewed from it
	node := f.idp.Service(t, "duckdb-secrets", "node", "nodes")
	g, r := f.grantFor(node, f.alice)
	if g == "" {
		t.Fatalf("a grant: %d %s", r.status, r.body)
	}
	if scope := f.idp.LastForm.Get("scope"); scope != "echo-api/.default offline_access" {
		t.Fatalf("the grant's OBO asks for a refresh token: %q", scope)
	}
	f.srv.now = func() time.Time { return time.Now().Add(290 * time.Second) }
	if renewed, _, r := f.mintedMaterial(node, "Delegation", g); renewed == "" || f.idp.Refreshed != 1 ||
		claimsOf(t, renewed)["sub"] != "alice-id" {
		t.Fatalf("renewed: %d %s (refreshes %d)", r.status, r.body, f.idp.Refreshed)
	}
	f.srv.now = time.Now

	// a scope of the secret's own is sent as it is
	f.do("DELETE", "/v1/secrets/echo", f.admin, "")
	if r := f.do("PUT", "/v1/secrets/echo", f.admin, strings.Replace(mintedSecret, `"audience":"echo-api"`,
		`"audience":"echo-api","scope":"echo-api/read"`, 1)); r.status != 201 {
		t.Fatalf("the secret again: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/echo/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	f.srv.direct = directCache{}
	if _, _, r := f.mintedMaterial(f.alice); f.idp.LastForm.Get("scope") != "echo-api/read" {
		t.Fatalf("the secret's scope: %q (%d)", f.idp.LastForm.Get("scope"), r.status)
	}

	// Entra's refusal: its code, never its message (names, trace ids); a 403 for the caller
	refused := f.idp.Token(t, testidp.Claims{"sub": "no-consent", "aud": []string{"duckdb-secrets"}, "azp": "duckdb",
		"realm_access": map[string]any{"roles": []any{"analysts"}}})
	r = f.do("GET", "/v1/secrets/echo", refused, "")
	if r.status != 403 || !strings.Contains(string(r.body), "AADSTS65001") || strings.Contains(string(r.body), "Trace ID") ||
		strings.Contains(string(r.body), "tresor'") {
		t.Fatalf("refused: %d %s", r.status, r.body)
	}
}
