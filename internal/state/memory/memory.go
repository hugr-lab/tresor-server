// Package memory is a state.Store in this process's memory: for tests, and for a service with nothing to
// keep. Everything is lost when the process ends.
package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/hugr-lab/tresor-server/internal/state"
)

// Store is safe for concurrent use. Writes are serialised, so fn runs once and never conflicts.
type Store struct {
	mu      sync.Mutex
	secrets map[string]*state.Secret
}

// New returns an empty store.
func New() *Store { return &Store{secrets: map[string]*state.Secret{}} }

func (s *Store) List(context.Context) ([]*state.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*state.Secret, 0, len(s.secrets))
	for _, sec := range s.secrets {
		listed := state.Clone(sec)
		listed.Params = nil // a list carries no material (state.Store)
		out = append(out, listed)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) Get(_ context.Context, name string) (*state.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.secrets[name]
	if !ok {
		return nil, state.ErrNotFound
	}
	return state.Clone(sec), nil
}

func (s *Store) Describe(ctx context.Context, name string) (*state.Secret, error) {
	sec, err := s.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	sec.Params = nil
	return sec, nil
}

func (s *Store) Update(ctx context.Context, name string,
	fn func(current *state.Secret) (*state.Secret, error)) (*state.Secret, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := state.Clone(s.secrets[name])
	next, err := fn(state.Clone(current))
	if err != nil {
		return nil, err
	}
	if err := state.CheckVersion(current, next); err != nil {
		return nil, err
	}
	if next == nil {
		if current == nil {
			return nil, state.ErrNotFound
		}
		delete(s.secrets, name)
		return nil, nil
	}
	next.Name = name
	s.secrets[name] = state.Clone(next)
	return next, nil
}

func (s *Store) Ping(context.Context) error { return nil }

func (s *Store) Close() error { return nil }
