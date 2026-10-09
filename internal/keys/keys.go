// Package keys is envelope encryption (spec 002): material is sealed with AES-256-GCM under a data key; data
// keys are wrapped by a KeyWrapper under a key-encryption key (KEK) the service does not keep at rest, and
// stored wrapped. Unwrapped data keys live in memory only, for a short time. Nothing here logs a key.
package keys

import (
	"context"
	"errors"
	"time"
)

// KeyWrapper wraps data keys under a KEK: a local key, or a key in a KMS.
type KeyWrapper interface {
	// Wrap wraps dek under the KEK's current version, and names that version (kekID).
	Wrap(ctx context.Context, dek []byte) (wrapped []byte, kekID string, err error)
	// Unwrap unwraps a data key wrapped under kekID.
	Unwrap(ctx context.Context, wrapped []byte, kekID string) ([]byte, error)
	// Current names the KEK's current version, as Wrap would: a new version means a new data key.
	Current(ctx context.Context) (kekID string, err error)
	// Root is a secret only the KEK's holder can compute, for the KEK version kekID names (spec 003): an RSA
	// KEK wraps with its public key, so a data key that unwraps proves nothing - the root authenticates it.
	// Deterministic, never stored.
	Root(ctx context.Context, kekID string) ([]byte, error)
	// Owns says whether kekID names a version of this KEK: a chain (spec 011) unwraps with the KEK that owns
	// the id, never by trying each.
	Owns(kekID string) bool
}

// DataKey is a data key as stored: wrapped, and authenticated by a tag under the KEK's root.
type DataKey struct {
	ID        string
	KEKID     string
	Wrapped   []byte
	Tag       []byte // HMAC under the root over the id, the KEK id and the wrapped bytes; nil before spec 003
	CreatedAt time.Time
}

// DataKeyStore keeps the wrapped data keys, and which one is active. Every state store provides one.
type DataKeyStore interface {
	// Get returns one data key, or ErrNoDataKey.
	Get(ctx context.Context, id string) (DataKey, error)
	// Active returns the active data key and the active slot's version, or ErrNoDataKey (version 0).
	Active(ctx context.Context) (DataKey, int64, error)
	// Activate stores dk and makes it the active one, compare-and-set on the slot's version (0: none yet).
	// Another replica that activated one first: ErrKeyRace, and the caller reads the winner's.
	Activate(ctx context.Context, dk DataKey, slotVersion int64) error
	// List returns every stored data key (rewrap).
	List(ctx context.Context) ([]DataKey, error)
	// Rewrapped replaces a data key's wrap and tag, compare-and-set on the KEK id it was read with; false
	// when another rewrap came first.
	Rewrapped(ctx context.Context, id, fromKEKID string, wrapped []byte, kekID string, tag []byte) (bool, error)
	// Delete removes a data key that is not the active one (spec 018: retired); false when there is none, or
	// it is the active one.
	Delete(ctx context.Context, id string) (bool, error)
}

var (
	// ErrNoDataKey: no such data key, or none active yet.
	ErrNoDataKey = errors.New("no such data key")
	// ErrKeyRace: another replica changed the active data key first.
	ErrKeyRace = errors.New("the active data key changed concurrently")
	// ErrSealed: a sealed value does not open - tampered with, moved to another row or version, or under
	// a data key that does not unwrap. Never an empty value instead.
	ErrSealed = errors.New("a sealed value does not open")
)
