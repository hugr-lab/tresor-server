// Package statetest is the one test suite every state.Store passes (spec 002): memory now, the SQL stores
// with the same suite.
package statetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hugr-lab/tresor-server/internal/state"
)

// Handles are a fresh, empty store and how to reach its database again.
type Handles struct {
	First state.Store
	// Another opens another handle on First's database, or is nil for a store with no database (memory).
	Another func() state.Store
	// Replicas: the handles serve side by side. Otherwise Another is a restart: it closes First first.
	Replicas bool
}

// Opener opens a store for one test; the store is closed with the test.
type Opener func(t *testing.T) Handles

// Run runs the suite.
func Run(t *testing.T, open Opener) {
	t.Run("CreateGetList", func(t *testing.T) { testCreateGetList(t, open) })
	t.Run("UpdateAndDelete", func(t *testing.T) { testUpdateAndDelete(t, open) })
	t.Run("Refusals", func(t *testing.T) { testRefusals(t, open) })
	t.Run("Isolation", func(t *testing.T) { testIsolation(t, open) })
	t.Run("ConcurrentWriters", func(t *testing.T) { testConcurrentWriters(t, open) })
	t.Run("SecondHandle", func(t *testing.T) { testSecondHandle(t, open) })
	t.Run("Delegations", func(t *testing.T) { testDelegations(t, open) })
	t.Run("DelegationLimit", func(t *testing.T) { testDelegationLimit(t, open) })
	t.Run("MintedTokens", func(t *testing.T) { testMintedTokens(t, open) })
}

var ctx = context.Background()

func secret(version int64) *state.Secret {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	return &state.Secret{
		Type: "s3", Provider: "config", Scope: []string{"s3://lake"},
		Params:     map[string]json.RawMessage{"key_id": json.RawMessage(`"AKIA"`), "secret": json.RawMessage(`{"type":"VARCHAR","value":"s"}`)},
		RedactKeys: []string{"secret"}, Comment: "c", Owner: "subject:iss|alice",
		CreatedAt: now, UpdatedAt: now, Version: version,
		Grants: []state.Grant{{ID: "g", Principal: "role:analysts", Verbs: []string{"use"}}},
	}
}

func create(t *testing.T, st state.Store, name string) *state.Secret {
	t.Helper()
	saved, err := st.Update(ctx, name, func(cur *state.Secret) (*state.Secret, error) {
		if cur != nil {
			t.Fatalf("%s exists already", name)
		}
		return secret(1), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func testCreateGetList(t *testing.T, open Opener) {
	st := open(t).First
	if _, err := st.Get(ctx, "a"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("a missing secret: %v", err)
	}
	for _, name := range []string{"b", "a", "c"} {
		if saved := create(t, st, name); saved.Name != name || saved.Version != 1 {
			t.Fatalf("created %+v", saved)
		}
	}
	got, err := st.Get(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	want := secret(1)
	want.Name = "a"
	if a, b := mustJSON(t, got), mustJSON(t, want); a != b {
		t.Fatalf("read back\n%s\nwant\n%s", a, b)
	}
	list, err := st.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || list[0].Name != "a" || list[1].Name != "b" || list[2].Name != "c" {
		t.Fatalf("list: %d secrets, not sorted by name", len(list))
	}
	listed := state.Clone(want)
	listed.Params = nil // a list carries no material, nor does a descriptor
	described, err := st.Describe(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if a, b := mustJSON(t, described), mustJSON(t, listed); a != b {
		t.Fatalf("described\n%s\nwant\n%s", a, b)
	}
	if _, err := st.Describe(ctx, "zz"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("describing a missing secret: %v", err)
	}
	if a, b := mustJSON(t, list[0]), mustJSON(t, listed); a != b {
		t.Fatalf("listed\n%s\nwant\n%s", a, b)
	}
	if err := st.Ping(ctx); err != nil {
		t.Fatal(err)
	}
}

func testUpdateAndDelete(t *testing.T, open Opener) {
	st := open(t).First
	create(t, st, "a")
	saved, err := st.Update(ctx, "a", func(cur *state.Secret) (*state.Secret, error) {
		cur.Comment = "changed"
		cur.Grants = append(cur.Grants, state.Grant{ID: "h", Principal: "group:ops", Verbs: []string{"use"}})
		cur.Version++
		return cur, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := st.Get(ctx, "a")
	if saved.Version != 2 || got.Version != 2 || got.Comment != "changed" || len(got.Grants) != 2 {
		t.Fatalf("updated: %+v", got)
	}
	if _, err := st.Update(ctx, "a", func(*state.Secret) (*state.Secret, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, "a"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if _, err := st.Update(ctx, "a", func(*state.Secret) (*state.Secret, error) { return nil, nil }); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("deleting a missing secret: %v", err)
	}
	// a dropped name can be created again, from version 1
	if saved := create(t, st, "a"); saved.Version != 1 {
		t.Fatalf("recreated at version %d", saved.Version)
	}
}

func testRefusals(t *testing.T, open Opener) {
	st := open(t).First
	create(t, st, "a")
	mine := errors.New("refused by fn")
	if _, err := st.Update(ctx, "a", func(*state.Secret) (*state.Secret, error) { return nil, mine }); !errors.Is(err, mine) {
		t.Fatalf("fn's error: %v", err)
	}
	if _, err := st.Update(ctx, "a", func(cur *state.Secret) (*state.Secret, error) {
		cur.Comment = "no version move"
		return cur, nil
	}); !errors.Is(err, state.ErrVersion) {
		t.Fatalf("a change that keeps the version: %v", err)
	}
	if _, err := st.Update(ctx, "b", func(*state.Secret) (*state.Secret, error) { return secret(3), nil }); !errors.Is(err, state.ErrVersion) {
		t.Fatalf("a create at version 3: %v", err)
	}
	got, _ := st.Get(ctx, "a")
	if got.Version != 1 || got.Comment != "c" {
		t.Fatalf("a refused write changed the secret: %+v", got)
	}
	if _, err := st.Get(ctx, "b"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("a refused create was kept: %v", err)
	}
}

// what a caller holds is its own: changing it changes nothing in the store
func testIsolation(t *testing.T, open Opener) {
	st := open(t).First
	saved := create(t, st, "a")
	saved.Grants[0].Verbs[0] = "delete"
	got, _ := st.Get(ctx, "a")
	got.Params["key_id"][1] = 'X'
	got.Scope[0] = "x"
	again, _ := st.Get(ctx, "a")
	if again.Grants[0].Verbs[0] != "use" || string(again.Params["key_id"]) != `"AKIA"` || again.Scope[0] != "s3://lake" {
		t.Fatalf("the store shares memory with its callers: %+v", again)
	}
}

// writers racing on one secret, through one handle and (where the store has them) through two, as two
// replicas: no increment is lost
func testConcurrentWriters(t *testing.T, open Opener) {
	h := open(t)
	first := h.First
	create(t, first, "a")
	stores := []state.Store{first}
	if h.Replicas {
		stores = append(stores, h.Another())
	}
	const writers, each = 8, 5
	var wg sync.WaitGroup
	var failed atomic.Int32
	for w := range writers {
		st := stores[w%len(stores)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				_, err := st.Update(ctx, "a", func(cur *state.Secret) (*state.Secret, error) {
					cur.Version++
					return cur, nil
				})
				if err != nil && !errors.Is(err, state.ErrConflict) {
					t.Error(err)
				}
				if err != nil {
					failed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	got, err := first.Get(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	// a write refused with ErrConflict did not happen; every other one did, once
	if want := int64(1 + writers*each - int(failed.Load())); got.Version != want {
		t.Fatalf("version %d after %d writes (%d conflicts): a write was lost or doubled", got.Version,
			writers*each, failed.Load())
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// another handle on the same database - a replica, or the store reopened - sees every write
func testSecondHandle(t *testing.T, open Opener) {
	h := open(t)
	first := h.First
	if h.Another == nil {
		t.Skip("no database to reach again")
	}
	create(t, first, "a")
	if _, err := first.Update(ctx, "a", func(cur *state.Secret) (*state.Secret, error) {
		cur.Grants = nil
		cur.Version++
		return cur, nil
	}); err != nil {
		t.Fatal(err)
	}
	other := h.Another()
	got, err := other.Get(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	want := secret(2)
	want.Name, want.Grants = "a", nil
	if a, b := mustJSON(t, got), mustJSON(t, want); a != b {
		t.Fatalf("through another handle\n%s\nwant\n%s", a, b)
	}
	if _, err := other.Update(ctx, "a", func(*state.Secret) (*state.Secret, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if !h.Replicas {
		return // the first handle is closed: a restart
	}
	if _, err := first.Get(ctx, "a"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("a delete through another handle: %v", err)
	}
}

func grant(id, actor, user string, expires time.Time) state.Delegation {
	return state.Delegation{IDHash: []byte("hash-" + id), ActorOwner: "subject:iss|" + actor, ActorClient: "client:" + actor,
		ActorIssuer: "iss", UserOwner: "subject:iss|" + user, User: []byte(`{"Subject":"` + user + `"}`),
		ExpiresAt: expires, Subject: []byte("subject-token-" + id), SubjectExpiresAt: expires.Add(-30 * time.Minute)}
}

func testDelegations(t *testing.T, open Opener) {
	h := open(t)
	d := h.First.Delegations()
	now := time.Now()
	g := grant("a", "node", "alice", now.Add(time.Hour))
	if err := d.Put(ctx, g, 10); err != nil {
		t.Fatal(err)
	}
	got, err := d.Get(ctx, g.IDHash, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.ActorOwner != g.ActorOwner || got.ActorClient != g.ActorClient || got.UserOwner != g.UserOwner ||
		string(got.User) != string(g.User) || got.Subject != nil || got.ExpiresAt.Sub(g.ExpiresAt).Abs() >= time.Microsecond {
		t.Fatalf("read back %+v", got)
	}
	if !got.HasSubject {
		t.Fatal("a kept subject token is not said to be")
	}
	if sub, err := d.SubjectToken(ctx, g.IDHash, now); err != nil || string(sub) != "subject-token-a" {
		t.Fatalf("the subject token: %q %v", sub, err)
	}
	// the subject token is not read after it expires, though the grant lives on
	if _, err := d.SubjectToken(ctx, g.IDHash, now.Add(45*time.Minute)); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("an expired subject token: %v", err)
	}
	if _, err := d.Get(ctx, g.IDHash, now.Add(45*time.Minute)); err != nil {
		t.Fatalf("the grant after its subject token expired: %v", err)
	}
	// an expired grant is not found
	if _, err := d.Get(ctx, g.IDHash, now.Add(2*time.Hour)); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("an expired grant: %v", err)
	}
	// a grant with no subject token kept
	bare := grant("b", "node", "bob", now.Add(time.Hour))
	bare.Subject = nil
	if err := d.Put(ctx, bare, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SubjectToken(ctx, bare.IDHash, now); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("no subject token kept: %v", err)
	}
	if got, _ := d.Get(ctx, bare.IDHash, now); got.HasSubject {
		t.Fatal("no subject token kept, but said to be")
	}
	// another handle (a replica, a restart) honours them
	if h.Another != nil {
		d = h.Another().Delegations()
		if _, err := d.Get(ctx, g.IDHash, now); err != nil {
			t.Fatalf("through another handle: %v", err)
		}
	}
	// revocation: by id, by actor, by user
	for _, gg := range []state.Delegation{grant("c", "other", "alice", now.Add(time.Hour)), grant("e", "other", "carol", now.Add(time.Hour))} {
		if err := d.Put(ctx, gg, 10); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := d.Delete(ctx, bare.IDHash); err != nil || !ok {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if ok, _ := d.Delete(ctx, bare.IDHash); ok {
		t.Fatal("deleted twice")
	}
	if n, err := d.DeleteWhere(ctx, "", "subject:iss|alice"); err != nil || n != 2 {
		t.Fatalf("by user: %d %v", n, err)
	}
	if n, err := d.DeleteWhere(ctx, "client:other", "subject:iss|nobody"); err != nil || n != 0 {
		t.Fatalf("by actor and user: %d %v", n, err)
	}
	if n, err := d.DeleteWhere(ctx, "client:other", ""); err != nil || n != 1 {
		t.Fatalf("by actor: %d %v", n, err)
	}
	if _, err := d.DeleteWhere(ctx, "", ""); err == nil {
		t.Fatal("revoking everything with no filter")
	}
	// purge: the expired grants go, with their tokens; a live one stays
	short, long := grant("s", "p", "u", now.Add(time.Minute)), grant("l", "p", "u", now.Add(time.Hour))
	for _, gg := range []state.Delegation{short, long} {
		if err := d.Put(ctx, gg, 10); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.PutToken(ctx, short.IDHash, state.MintedToken{Key: "k", Version: 1, Token: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if n, err := d.Purge(ctx, now.Add(10*time.Minute)); err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if _, err := d.Token(ctx, short.IDHash, "k"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("a purged grant's token: %v", err)
	}
	if _, err := d.Get(ctx, long.IDHash, now); err != nil {
		t.Fatalf("a live grant purged: %v", err)
	}
}

// the limit is per actor, taken with the insert: racing puts never pass it
func testDelegationLimit(t *testing.T, open Opener) {
	d := open(t).First.Delegations()
	now := time.Now()
	const limit = 5
	var wg sync.WaitGroup
	var ok, full atomic.Int32
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := d.Put(ctx, grant(fmt.Sprint(i), "node", "alice", now.Add(time.Hour)), limit)
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, state.ErrTooMany):
				full.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != limit || full.Load() != 20-limit {
		t.Fatalf("%d put, %d refused: the limit is %d", ok.Load(), full.Load(), limit)
	}
	if n, _ := d.Count(ctx, "subject:iss|node", now); n != limit {
		t.Fatalf("count %d", n)
	}
	// another actor has its own room; an expired grant takes none
	if err := d.Put(ctx, grant("x", "other", "alice", now.Add(time.Hour)), limit); err != nil {
		t.Fatalf("another actor: %v", err)
	}
	if n, _ := d.Count(ctx, "subject:iss|node", now.Add(2*time.Hour)); n != 0 {
		t.Fatalf("expired grants counted: %d", n)
	}
}

func testMintedTokens(t *testing.T, open Opener) {
	const key = "aud\x00scope" // as the API makes one: the audience and the scope, NUL between
	d := open(t).First.Delegations()
	now := time.Now()
	g := grant("a", "node", "alice", now.Add(time.Hour))
	if err := d.Put(ctx, g, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Token(ctx, g.IDHash, key); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("no token yet: %v", err)
	}
	put := func(v int64, token, failed string) error {
		var raw []byte
		if token != "" {
			raw = []byte(token)
		}
		return d.PutToken(ctx, g.IDHash, state.MintedToken{Key: key, Version: v, Token: raw, Failed: failed})
	}
	if err := put(1, `{"access":"t1"}`, ""); err != nil {
		t.Fatal(err)
	}
	if err := put(1, `{"access":"other"}`, ""); !errors.Is(err, state.ErrConflict) {
		t.Fatalf("a second first token: %v", err)
	}
	if err := put(2, `{"access":"t2"}`, ""); err != nil {
		t.Fatal(err)
	}
	if err := put(2, `{"access":"stale"}`, ""); !errors.Is(err, state.ErrConflict) {
		t.Fatalf("a renewal from a stale version: %v", err)
	}
	tok, err := d.Token(ctx, g.IDHash, key)
	if err != nil || tok.Version != 2 || string(tok.Token) != `{"access":"t2"}` || tok.Failed != "" {
		t.Fatalf("the token: %+v %v", tok, err)
	}
	if err := put(3, "", "the IdP refused"); err != nil {
		t.Fatal(err)
	}
	if tok, _ := d.Token(ctx, g.IDHash, key); tok.Token != nil || tok.Failed != "the IdP refused" {
		t.Fatalf("a refusal kept: %+v", tok)
	}
	// the grant's tokens go with it; a token for a grant that is gone is not stored
	if _, err := d.Delete(ctx, g.IDHash); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Token(ctx, g.IDHash, key); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("a token outlives its grant: %v", err)
	}
	if err := put(1, `{"access":"x"}`, ""); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("a token for a grant that is gone: %v", err)
	}
}
