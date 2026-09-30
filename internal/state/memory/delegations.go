package memory

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/hugr-lab/tresor-server/internal/state"
)

// delegations keep the grants in this process's memory (tests, a memory store).
type delegations struct {
	mu     sync.Mutex
	grants map[string]*state.Delegation
	tokens map[string]map[string]*state.MintedToken // id hash -> key -> token
}

func (s *Store) Delegations() state.DelegationStore { return s.delegations }

func key(idHash []byte) string { return hex.EncodeToString(idHash) }

func cloneDelegation(d *state.Delegation) *state.Delegation {
	out := *d
	out.IDHash, out.User, out.Subject = bytes.Clone(d.IDHash), bytes.Clone(d.User), bytes.Clone(d.Subject)
	return &out
}

func (d *delegations) purge(now time.Time) {
	for k, g := range d.grants {
		if !now.Before(g.ExpiresAt) {
			delete(d.grants, k)
			delete(d.tokens, k)
		}
	}
}

func (d *delegations) Put(_ context.Context, g state.Delegation, maxPerActor int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	d.purge(now)
	n := 0
	for _, other := range d.grants {
		if other.ActorOwner == g.ActorOwner {
			n++
		}
	}
	if n >= maxPerActor {
		return state.ErrTooMany
	}
	d.grants[key(g.IDHash)] = cloneDelegation(&g)
	return nil
}

func (d *delegations) Count(_ context.Context, actorOwner string, now time.Time) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, g := range d.grants {
		if g.ActorOwner == actorOwner && now.Before(g.ExpiresAt) {
			n++
		}
	}
	return n, nil
}

func (d *delegations) live(idHash []byte, now time.Time) *state.Delegation {
	g := d.grants[key(idHash)]
	if g == nil || !now.Before(g.ExpiresAt) {
		return nil
	}
	return g
}

func (d *delegations) Get(_ context.Context, idHash []byte, now time.Time) (*state.Delegation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	g := d.live(idHash, now)
	if g == nil {
		return nil, state.ErrNotFound
	}
	out := cloneDelegation(g)
	out.Subject = nil
	return out, nil
}

func (d *delegations) SubjectToken(_ context.Context, idHash []byte, now time.Time) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	g := d.live(idHash, now)
	if g == nil || g.Subject == nil || !now.Before(g.SubjectExpiresAt) {
		return nil, state.ErrNotFound
	}
	return bytes.Clone(g.Subject), nil
}

func (d *delegations) Delete(_ context.Context, idHash []byte) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.grants[key(idHash)]
	delete(d.grants, key(idHash))
	delete(d.tokens, key(idHash))
	return ok, nil
}

func (d *delegations) DeleteWhere(_ context.Context, actorClient, userOwner string) (int, error) {
	if actorClient == "" && userOwner == "" {
		return 0, errors.New("revoking grants names an actor or a user")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for k, g := range d.grants {
		if (actorClient == "" || g.ActorClient == actorClient) && (userOwner == "" || g.UserOwner == userOwner) {
			delete(d.grants, k)
			delete(d.tokens, k)
			n++
		}
	}
	return n, nil
}

func (d *delegations) Token(_ context.Context, idHash []byte, k string) (*state.MintedToken, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t := d.tokens[key(idHash)][k]
	if t == nil {
		return nil, state.ErrNotFound
	}
	out := *t
	out.Token = bytes.Clone(t.Token)
	return &out, nil
}

func (d *delegations) PutToken(_ context.Context, idHash []byte, t state.MintedToken) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.grants[key(idHash)] == nil {
		return state.ErrNotFound
	}
	byKey := d.tokens[key(idHash)]
	if byKey == nil {
		byKey = map[string]*state.MintedToken{}
		d.tokens[key(idHash)] = byKey
	}
	var current int64
	if old := byKey[t.Key]; old != nil {
		current = old.Version
	}
	if t.Version != current+1 {
		return state.ErrConflict
	}
	stored := t
	stored.Token = slices.Clone(t.Token)
	byKey[t.Key] = &stored
	return nil
}
