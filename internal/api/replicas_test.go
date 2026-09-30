package api

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

// replica is a second server on the fixture's store, as another replica behind the same load balancer.
func (f *fixture) replica(t *testing.T) (*fixture, *Server) {
	t.Helper()
	srv, err := New(context.Background(), f.srv.cfg, f.srv.verifier, f.srv.store, f.srv.log)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(srv.Handler())
	t.Cleanup(server.Close)
	other := *f
	other.base, other.srv = server.URL, srv
	return &other, srv
}

// a grant made on one replica is honoured on another; its minted token, renewed from the refresh token on
// the other after the subject token expired, is the one both serve; revoked on one, it is gone on both
func TestGrantsAcrossReplicas(t *testing.T) {
	a := newFixture(t, "")
	b, bsrv := a.replica(t)
	node := a.idp.Service(t, "duckdb-secrets", "node", "nodes")
	a.do("PUT", "/v1/secrets/echo", a.admin, mintedSecret)
	a.do("PUT", "/v1/secrets/echo/grants/n", a.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	g, r := a.grantFor(node, a.alice)
	if g == "" {
		t.Fatalf("exchange on a: %d %s", r.status, r.body)
	}
	if r := b.do("GET", "/v1/whoami", node, "", "Delegation", g); r.status != 200 || r.json(t)["subject"] != "alice-id" {
		t.Fatalf("the grant on b: %d %s", r.status, r.body)
	}
	// six minutes on: the subject token and the minted token have expired; b renews from the stored refresh
	// token - a replica that never saw the exchange
	later := func() time.Time { return time.Now().Add(6 * time.Minute) }
	bsrv.now, a.srv.now = later, later
	renewed, _, r := b.mintedMaterial(node, "Delegation", g)
	if renewed == "" || claimsOf(t, renewed)["sub"] != "alice-id" || a.idp.Refreshed != 1 {
		t.Fatalf("renewed on b: %d %s (refreshes %d)", r.status, r.body, a.idp.Refreshed)
	}
	// a serves b's token: no second refresh (the refresh token was spent once)
	if same, _, r := a.mintedMaterial(node, "Delegation", g); same != renewed || a.idp.Refreshed != 1 {
		t.Fatalf("a after b renewed: %d %s (refreshes %d)", r.status, r.body, a.idp.Refreshed)
	}
	bsrv.now, a.srv.now = time.Now, time.Now
	// revoked on b: gone on a
	if r := b.do("DELETE", "/v1/delegations/"+g, node, ""); r.status != 204 {
		t.Fatalf("revoke on b: %d %s", r.status, r.body)
	}
	if r := a.do("GET", "/v1/whoami", node, "", "Delegation", g); r.status != 401 {
		t.Fatalf("a revoked grant on a: %d", r.status)
	}
}
