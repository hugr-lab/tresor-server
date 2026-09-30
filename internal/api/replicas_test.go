package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hugr-lab/tresor-server/internal/state"
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

// flaky wraps the store's delegations: before PutToken stores a token, hook may act as another replica, or
// fail as a store would
type flaky struct {
	state.Store
	d *flakyDelegations
}

func (f *flaky) Delegations() state.DelegationStore { return f.d }

type flakyDelegations struct {
	state.DelegationStore
	hook func(idHash []byte, t state.MintedToken) error
}

func (d *flakyDelegations) PutToken(ctx context.Context, idHash []byte, t state.MintedToken) error {
	if d.hook != nil {
		if err := d.hook(idHash, t); err != nil {
			return err
		}
	}
	return d.DelegationStore.PutToken(ctx, idHash, t)
}

func wrapDelegations(f *fixture) *flakyDelegations {
	d := &flakyDelegations{DelegationStore: f.srv.store.Delegations()}
	f.srv.store = &flaky{Store: f.srv.store, d: d}
	return d
}

// another replica tried the refresh token this one had just spent, got invalid_grant and wrote the session
// ended: the good token this replica holds goes over that failure, not the other way round
func TestRenewalRaceKeepsTheGoodToken(t *testing.T) {
	f := newFixture(t, "")
	node := f.idp.Service(t, "duckdb-secrets", "node", "nodes")
	f.do("PUT", "/v1/secrets/echo", f.admin, mintedSecret)
	f.do("PUT", "/v1/secrets/echo/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	g, r := f.grantFor(node, f.alice)
	if g == "" {
		t.Fatalf("exchange: %d %s", r.status, r.body)
	}
	d := wrapDelegations(f)
	inner := d.DelegationStore
	d.hook = func(idHash []byte, tok state.MintedToken) error {
		if tok.Token != nil {
			d.hook = nil // once: the other replica's failure lands first
			return inner.PutToken(context.Background(), idHash, state.MintedToken{Key: tok.Key, Version: tok.Version,
				Failed: "the user's session at the identity provider has ended"})
		}
		return nil
	}
	f.srv.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	renewed, _, r := f.mintedMaterial(node, "Delegation", g)
	if renewed == "" || claimsOf(t, renewed)["sub"] != "alice-id" {
		t.Fatalf("the renewed token after the race: %d %s", r.status, r.body)
	}
	// and it is what is kept: the next read serves it, no refresh, no refusal
	if again, _, r := f.mintedMaterial(node, "Delegation", g); again != renewed || f.idp.Refreshed != 1 {
		t.Fatalf("kept: %d %s (refreshes %d)", r.status, r.body, f.idp.Refreshed)
	}
}

// a renewed token the store fails to keep is tried again; when it cannot be kept, the answer is an outage
func TestRenewedTokenStoreFails(t *testing.T) {
	f := newFixture(t, "")
	node := f.idp.Service(t, "duckdb-secrets", "node", "nodes")
	f.do("PUT", "/v1/secrets/echo", f.admin, mintedSecret)
	f.do("PUT", "/v1/secrets/echo/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	g, _ := f.grantFor(node, f.alice)
	d := wrapDelegations(f)
	fails := 2
	d.hook = func([]byte, state.MintedToken) error {
		if fails > 0 {
			fails--
			return errors.New("disk I/O error")
		}
		return nil
	}
	f.srv.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	if renewed, _, r := f.mintedMaterial(node, "Delegation", g); renewed == "" {
		t.Fatalf("stored on the third try: %d %s", r.status, r.body)
	}
	d.hook = func([]byte, state.MintedToken) error { return errors.New("disk I/O error") }
	f.srv.now = func() time.Time { return time.Now().Add(12 * time.Minute) }
	if _, _, r := f.mintedMaterial(node, "Delegation", g); r.status != 503 || r.problemType(t) != "service_unavailable" {
		t.Fatalf("never stored: %d %s", r.status, r.body)
	}
}
