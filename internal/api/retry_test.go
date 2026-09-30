package api

import (
	"context"
	"sync"
	"testing"

	"github.com/hugr-lab/tresor-server/internal/state"
)

// racing is a store whose first Update of a name loses a race, as on a replicated store: fn runs on what the
// caller last saw, then again on the secret another replica wrote meanwhile.
type racing struct {
	state.Store
	mu     sync.Mutex
	stale  map[string]*state.Secret // what fn sees first; nil: the name was missing
	raced  map[string]bool
	before map[string]bool
}

func (r *racing) Update(ctx context.Context, name string,
	fn func(current *state.Secret) (*state.Secret, error)) (*state.Secret, error) {
	r.mu.Lock()
	first := !r.raced[name] && r.before[name]
	r.raced[name] = true
	stale := r.stale[name]
	r.mu.Unlock()
	if first {
		if _, err := fn(state.Clone(stale)); err != nil {
			return nil, err // fn refused: a store writes nothing and runs fn no more
		}
		// the write would have been compare-and-set on a version that moved on: fn runs again
	}
	return r.Store.Update(ctx, name, fn)
}

// a handler's answer comes from fn's last run, never a former one (state.Store: fn may run again)
func TestUpdateRetried(t *testing.T) {
	f := newFixture(t, "")
	if r := f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret); r.status != 201 {
		t.Fatalf("seed: %d %s", r.status, r.body)
	}
	// another replica created "lake" after this one looked: the update's first run sees no secret
	f.srv.store = &racing{Store: f.srv.store, stale: map[string]*state.Secret{}, raced: map[string]bool{},
		before: map[string]bool{"lake": true}}
	if got := f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret); got.status != 200 {
		t.Fatalf("an update whose first run saw a create: %d %s (want 200)", got.status, got.body)
	}
}
