// Package statetest is the one test suite every state.Store passes (spec 002): memory now, the SQL stores
// with the same suite.
package statetest

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hugr-lab/tresor-server/internal/state"
)

// Opener returns a fresh, empty store, and - for a store that can have several handles on one database, as
// replicas have - a function that opens another handle on it. A store that cannot returns nil for it, and
// the concurrent writers then share one handle.
type Opener func(t *testing.T) (first state.Store, second func() state.Store)

// Run runs the suite.
func Run(t *testing.T, open Opener) {
	t.Run("CreateGetList", func(t *testing.T) { testCreateGetList(t, open) })
	t.Run("UpdateAndDelete", func(t *testing.T) { testUpdateAndDelete(t, open) })
	t.Run("Refusals", func(t *testing.T) { testRefusals(t, open) })
	t.Run("Isolation", func(t *testing.T) { testIsolation(t, open) })
	t.Run("ConcurrentWriters", func(t *testing.T) { testConcurrentWriters(t, open) })
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
	st, _ := open(t)
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
	if err := st.Ping(ctx); err != nil {
		t.Fatal(err)
	}
}

func testUpdateAndDelete(t *testing.T, open Opener) {
	st, _ := open(t)
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
	st, _ := open(t)
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
	st, _ := open(t)
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
	first, second := open(t)
	create(t, first, "a")
	stores := []state.Store{first}
	if second != nil {
		if other := second(); other != nil {
			stores = append(stores, other)
		}
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
