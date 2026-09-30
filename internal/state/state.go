// Package state is what the service knows about secrets, behind one interface for every store (spec 002):
// memory, and the SQL stores to come. Every write goes through Update, compare-and-set on the version.
// Nothing here logs material.
package state

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// Secret is one stored secret. Params keep the protocol's typed values verbatim.
type Secret struct {
	Name       string                     `json:"name"`
	Type       string                     `json:"type"`
	Provider   string                     `json:"provider"`
	Scope      []string                   `json:"scope"`
	Params     map[string]json.RawMessage `json:"params"`
	RedactKeys []string                   `json:"redact_keys"`
	Comment    string                     `json:"comment"`
	Owner      string                     `json:"owner"`
	CreatedAt  time.Time                  `json:"created_at"`
	UpdatedAt  time.Time                  `json:"updated_at"`
	// Version is the protocol's (the ETag): every write moves it, and the compare-and-set is on it.
	Version int64   `json:"version"`
	Grants  []Grant `json:"grants"`
}

// Grant gives a principal verbs on one secret.
type Grant struct {
	ID        string   `json:"id"`
	Principal string   `json:"principal"`
	Verbs     []string `json:"verbs"`
}

var (
	// ErrNotFound: no such secret.
	ErrNotFound = errors.New("not found")
	// ErrConflict: the secret kept changing under an Update, past its retries.
	ErrConflict = errors.New("the secret changed concurrently")
	// ErrVersion: fn returned a secret whose version does not move on from the current one.
	ErrVersion = errors.New("a write must move the version on")
	// ErrUnavailable: this replica may not use the store now (SQLite: another replica holds the lease).
	ErrUnavailable = errors.New("the store is held by another replica")
)

// Store keeps the secrets. Implementations are safe for concurrent use, across replicas where the store
// allows several.
type Store interface {
	// List returns every secret, sorted by name, without its params: a list opens no material (spec 002),
	// so one value that does not open never fails a whole list.
	List(ctx context.Context) ([]*Secret, error)
	// Describe returns one secret without its params, or ErrNotFound: what a descriptor or a permission
	// needs opens no material.
	Describe(ctx context.Context, name string) (*Secret, error)
	// Get returns one secret with its params, or ErrNotFound. Params that do not open are an error, never
	// an empty value (keys.ErrSealed).
	Get(ctx context.Context, name string) (*Secret, error)
	// Update is the one write path. fn gets a copy of the current secret (nil when absent) and returns the
	// next one (nil: delete; ErrNotFound when there is nothing to delete) or an error that aborts the
	// write and is returned as it is. A new secret has version 1; a changed one a version above the
	// current one. The write is compare-and-set on the version: when another write came first, fn runs
	// again on the fresh secret - so fn must not keep state from a former run - a bounded number of
	// times, then ErrConflict.
	Update(ctx context.Context, name string, fn func(current *Secret) (*Secret, error)) (*Secret, error)
	// Delegations are the delegation grants, in the same database.
	Delegations() DelegationStore
	// Ping says whether the store answers.
	Ping(ctx context.Context) error
	Close() error
}

// Clone is a deep copy of sec: what a store hands out and keeps is never shared with its callers.
func Clone(sec *Secret) *Secret {
	if sec == nil {
		return nil
	}
	out := *sec
	out.Scope = slices.Clone(sec.Scope)
	out.RedactKeys = slices.Clone(sec.RedactKeys)
	if sec.Params != nil {
		out.Params = make(map[string]json.RawMessage, len(sec.Params))
		for k, v := range sec.Params {
			out.Params[k] = slices.Clone(v)
		}
	}
	if sec.Grants != nil {
		out.Grants = make([]Grant, len(sec.Grants))
		for i, g := range sec.Grants {
			out.Grants[i] = Grant{ID: g.ID, Principal: g.Principal, Verbs: slices.Clone(g.Verbs)}
		}
	}
	return &out
}

// CheckVersion is the rule every store applies to what fn returned: a new secret starts at 1, a change moves
// the version on.
func CheckVersion(current, next *Secret) error {
	switch {
	case next == nil:
		return nil
	case current == nil && next.Version != 1:
		return ErrVersion
	case current != nil && next.Version <= current.Version:
		return ErrVersion
	}
	return nil
}
