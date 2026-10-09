// Package statetest is the one test suite every state.Store passes (spec 002): memory now, the SQL stores
// with the same suite.
package statetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hugr-lab/tresor-server/internal/keys"
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
	t.Run("ExactNames", func(t *testing.T) { testExactNames(t, open) })
	t.Run("ConcurrentWriters", func(t *testing.T) { testConcurrentWriters(t, open) })
	t.Run("SecondHandle", func(t *testing.T) { testSecondHandle(t, open) })
	t.Run("Delegations", func(t *testing.T) { testDelegations(t, open) })
	t.Run("DelegationLimit", func(t *testing.T) { testDelegationLimit(t, open) })
	t.Run("MintedTokens", func(t *testing.T) { testMintedTokens(t, open) })
	t.Run("Namespaces", func(t *testing.T) { testNamespaces(t, open) })
	t.Run("Reseal", func(t *testing.T) { testReseal(t, open) })
	// spec 004: the variables' namespace keeps to the same rules
	variables := func(t *testing.T) Handles {
		h := open(t)
		v := Handles{First: h.First.Variables(), Replicas: h.Replicas}
		if h.Another != nil {
			v.Another = func() state.Store { return h.Another().Variables() }
		}
		return v
	}
	t.Run("Variables", func(t *testing.T) {
		t.Run("CreateGetList", func(t *testing.T) { testCreateGetList(t, variables) })
		t.Run("UpdateAndDelete", func(t *testing.T) { testUpdateAndDelete(t, variables) })
		t.Run("Refusals", func(t *testing.T) { testRefusals(t, variables) })
		t.Run("Isolation", func(t *testing.T) { testIsolation(t, variables) })
		t.Run("ExactNames", func(t *testing.T) { testExactNames(t, variables) })
		t.Run("ConcurrentWriters", func(t *testing.T) { testConcurrentWriters(t, variables) })
		t.Run("SecondHandle", func(t *testing.T) { testSecondHandle(t, variables) })
	})
}

// the secrets and the variables are two namespaces: one name in both is two entries, and a delete in one
// leaves the other
func testNamespaces(t *testing.T, open Opener) {
	st := open(t).First
	vars := st.Variables()
	if vars.Variables() != vars {
		t.Fatal("the variables' own Variables is not itself")
	}
	create(t, st, "lake")
	if _, err := vars.Get(ctx, "lake"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("a secret seen as a variable: %v", err)
	}
	v := create(t, vars, "lake")
	v.Comment = "the variable"
	if _, err := vars.Update(ctx, "lake", func(cur *state.Secret) (*state.Secret, error) {
		cur.Comment, cur.Version = "the variable", cur.Version+1
		return cur, nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get(ctx, "lake"); got.Comment != "c" || got.Version != 1 {
		t.Fatalf("a variable's write changed the secret: %+v", got)
	}
	if _, err := st.Update(ctx, "lake", func(*state.Secret) (*state.Secret, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if got, err := vars.Get(ctx, "lake"); err != nil || got.Comment != "the variable" {
		t.Fatalf("a secret's delete took the variable: %v", err)
	}
	if list, _ := vars.List(ctx); len(list) != 1 {
		t.Fatalf("%d variables", len(list))
	}
	if list, _ := st.List(ctx); len(list) != 0 {
		t.Fatalf("%d secrets", len(list))
	}
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

// names are compared exactly (the protocol): names that differ only by case are two secrets, whatever the
// database's default collation
func testExactNames(t *testing.T, open Opener) {
	st := open(t).First
	create(t, st, "lake")
	create(t, st, "Lake")
	if _, err := st.Update(ctx, "LAKE", func(cur *state.Secret) (*state.Secret, error) {
		if cur != nil {
			t.Fatal("LAKE found another name's secret")
		}
		return nil, errors.New("stop")
	}); err == nil {
		t.Fatal("no fn run")
	}
	if _, err := st.Update(ctx, "Lake", func(*state.Secret) (*state.Secret, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if got, err := st.Get(ctx, "lake"); err != nil || got.Name != "lake" {
		t.Fatalf("deleting Lake touched lake: %v", err)
	}
	if list, _ := st.List(ctx); len(list) != 1 {
		t.Fatalf("%d secrets after deleting Lake", len(list))
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

// spec 018: every row moves to the active data key, its version kept; the data keys nothing uses are retired,
// and every row still reads
func testReseal(t *testing.T, open Opener) {
	h := open(t)
	st := h.First
	rs, ok := st.(state.Resealer)
	sealed, enveloped := st.(interface{ Envelope() *keys.Envelope })
	if !ok || !enveloped {
		t.Skip("nothing at rest")
	}
	env := sealed.Envelope()
	d := st.Delegations()
	now := time.Now()
	const key = "aud\x00scope"

	// under the first data key: a secret, a variable, a grant with its subject and its minted token, one without
	first, err := env.ActiveID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	create(t, st, "a")
	create(t, st.Variables(), "v")
	withSubject, without := grant("a", "node", "alice", now.Add(time.Hour)), grant("b", "node", "bob", now.Add(time.Hour))
	without.Subject = nil
	for _, g := range []state.Delegation{withSubject, without} {
		if err := d.Put(ctx, g, 10); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.PutToken(ctx, withSubject.IDHash, state.MintedToken{Key: key, Version: 1, Token: []byte("minted")}); err != nil {
		t.Fatal(err)
	}
	// under the second: another secret; then a third is the active one
	second, err := env.Rotate(ctx)
	if err != nil || second == first {
		t.Fatalf("rotate: %s %v", second, err)
	}
	create(t, st, "b")
	active, err := env.Rotate(ctx)
	if err != nil || active == second {
		t.Fatalf("rotate: %s %v", active, err)
	}

	if n, err := rs.RowsBehind(ctx, active); err != nil || n < 5 {
		t.Fatalf("rows behind the active key before the reseal: %d %v", n, err)
	}
	if status, err := env.Status(ctx); err != nil || len(status.IDs) != 3 || status.ActiveID != active || status.Oldest.After(status.Active) {
		t.Fatalf("the data keys' status: %+v %v", status, err)
	}
	moved, skipped, err := rs.Reseal(ctx)
	if err != nil || skipped != 0 || moved < 5 {
		t.Fatalf("reseal: moved %d, skipped %d, %v", moved, skipped, err)
	}
	if again, _, err := rs.Reseal(ctx); err != nil || again != 0 {
		t.Fatalf("a second reseal moves nothing: %d %v", again, err)
	}
	inUse, err := rs.DataKeysInUse(ctx)
	if err != nil || !inUse[active] || inUse[second] {
		t.Fatalf("in use after the reseal: %v %v", inUse, err)
	}
	// every row as it was: its version, its material
	reads := func(when string, subject bool) {
		t.Helper()
		for _, e := range []struct {
			st   state.Store
			name string
		}{{st, "a"}, {st, "b"}, {st.Variables(), "v"}} {
			got, err := e.st.Get(ctx, e.name)
			if err != nil || got.Version != 1 || mustJSON(t, got.Params) != mustJSON(t, secret(1).Params) {
				t.Fatalf("%s: %s: %+v %v", when, e.name, got, err)
			}
		}
		if !subject {
			// its grant deleted
		} else if got, err := d.SubjectToken(ctx, withSubject.IDHash, now); err != nil || string(got) != string(withSubject.Subject) {
			t.Fatalf("%s: the subject: %q %v", when, got, err)
		}
		if _, err := d.Get(ctx, without.IDHash, now); err != nil {
			t.Fatalf("%s: a grant with no subject: %v", when, err)
		}
	}
	reads("resealed", true)
	if tok, err := d.Token(ctx, withSubject.IDHash, key); err != nil || string(tok.Token) != "minted" || tok.Version != 1 {
		t.Fatalf("resealed: the minted token: %+v %v", tok, err)
	}

	// retired: the active key made just now, nothing goes; an hour on, every key nothing uses
	kept, err := env.Retire(ctx, inUse)
	if err != nil || len(kept) != 2 || kept[0].Reason == "" || kept[1].Reason == "" {
		t.Fatalf("the active key made just now: %+v %v", kept, err)
	}
	env.SetClock(func() time.Time { return time.Now().Add(time.Hour) })
	defer env.SetClock(time.Now)
	retired := map[string]bool{}
	retire := func() {
		t.Helper()
		if inUse, err = rs.DataKeysInUse(ctx); err != nil {
			t.Fatal(err)
		}
		got, err := env.Retire(ctx, inUse)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range got {
			if r.Reason == "" {
				retired[r.ID] = true
			}
		}
	}
	retire()
	if !retired[second] {
		t.Fatalf("the second key, used by nothing, retired: %v", retired)
	}
	reads("retired", true)
	if tok, err := d.Token(ctx, withSubject.IDHash, key); err != nil || string(tok.Token) != "minted" {
		t.Fatalf("a token kept under its data key (a SQL store) keeps it: %+v %v", tok, err)
	}
	// the token's grant gone: nothing is under the first key any more - every row left it
	if _, err := d.Delete(ctx, withSubject.IDHash); err != nil {
		t.Fatal(err)
	}
	retire()
	if n, err := rs.RowsBehind(ctx, active); err != nil || n != 0 {
		t.Fatalf("rows behind once every key but the active one is gone: %d %v", n, err)
	}
	if !retired[first] || len(inUse) != 1 || !inUse[active] {
		t.Fatalf("only the active key is used, the others retired: in use %v, retired %v", inUse, retired)
	}
	for _, id := range []string{first, second} {
		if _, err := env.Open(ctx, id, []byte("x"), make([]byte, 32)); err == nil || !strings.Contains(err.Error(), "is not stored") {
			t.Fatalf("data key %s is gone: %v", id, err)
		}
	}
	reads("all retired", false)
	if h.Another != nil && h.Replicas {
		if got, err := h.Another().Get(ctx, "a"); err != nil || got.Version != 1 {
			t.Fatalf("another replica reads it: %+v %v", got, err)
		}
	}
}
