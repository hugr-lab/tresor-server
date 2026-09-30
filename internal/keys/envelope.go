package keys

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Envelope seals and opens values under the active data key. It is safe for concurrent use.
type Envelope struct {
	wrapper KeyWrapper
	keys    DataKeyStore
	maxAge  time.Duration // the active data key's age before a new one is made
	ttl     time.Duration // how long an unwrapped data key stays in memory
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]cached // data key id -> unwrapped
}

type cached struct {
	aead    cipher.AEAD
	expires time.Time
}

// Options tune an envelope; zero values take the defaults (spec 002: 30 days, 5 minutes).
type Options struct {
	DataKeyMaxAge time.Duration
	CacheTTL      time.Duration
}

// NewEnvelope returns an envelope over a wrapper and a store of data keys.
func NewEnvelope(wrapper KeyWrapper, keys DataKeyStore, opts Options) *Envelope {
	if opts.DataKeyMaxAge <= 0 {
		opts.DataKeyMaxAge = 30 * 24 * time.Hour
	}
	if opts.CacheTTL <= 0 {
		opts.CacheTTL = 5 * time.Minute
	}
	return &Envelope{wrapper: wrapper, keys: keys, maxAge: opts.DataKeyMaxAge, ttl: opts.CacheTTL,
		now: time.Now, cache: map[string]cached{}}
}

// Seal encrypts plain under the active data key with aad bound to it; it names the data key it used.
func (e *Envelope) Seal(ctx context.Context, aad, plain []byte) (dataKeyID string, sealed []byte, err error) {
	id, aead, err := e.active(ctx)
	if err != nil {
		return "", nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, err
	}
	return id, aead.Seal(nonce, nonce, plain, aad), nil
}

// Open decrypts a sealed value; anything that does not open - a wrong data key, aad or byte - is ErrSealed.
func (e *Envelope) Open(ctx context.Context, dataKeyID string, aad, sealed []byte) ([]byte, error) {
	aead, err := e.aead(ctx, dataKeyID)
	if err != nil {
		return nil, err
	}
	n := aead.NonceSize()
	if len(sealed) < n {
		return nil, ErrSealed
	}
	plain, err := aead.Open(nil, sealed[:n], sealed[n:], aad)
	if err != nil {
		return nil, ErrSealed
	}
	return plain, nil
}

// Check wraps and unwraps a throwaway key: the KEK answers (readiness).
func (e *Envelope) Check(ctx context.Context) error {
	probe := make([]byte, 32)
	if _, err := rand.Read(probe); err != nil {
		return err
	}
	wrapped, kekID, err := e.wrapper.Wrap(ctx, probe)
	if err != nil {
		return fmt.Errorf("the KEK does not wrap: %w", err)
	}
	back, err := e.wrapper.Unwrap(ctx, wrapped, kekID)
	if err != nil || string(back) != string(probe) {
		return errors.New("the KEK does not unwrap what it wrapped")
	}
	return nil
}

// Rewrap wraps every data key under the KEK's current version, where it is not already: after a rotation
// of the KEK, its old versions can be retired. The values sealed under the data keys are not touched. How
// many were rewrapped.
func (e *Envelope) Rewrap(ctx context.Context) (int, error) {
	current, err := e.wrapper.Current(ctx)
	if err != nil {
		return 0, fmt.Errorf("the KEK: %w", err)
	}
	all, err := e.keys.List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, dk := range all {
		if dk.KEKID == current {
			continue
		}
		dek, err := e.wrapper.Unwrap(ctx, dk.Wrapped, dk.KEKID)
		if err != nil {
			return n, fmt.Errorf("data key %s: %w", dk.ID, err)
		}
		wrapped, kekID, err := e.wrapper.Wrap(ctx, dek)
		clear(dek)
		if err != nil {
			return n, fmt.Errorf("data key %s: %w", dk.ID, err)
		}
		ok, err := e.keys.Rewrapped(ctx, dk.ID, dk.KEKID, wrapped, kekID)
		if err != nil {
			return n, fmt.Errorf("data key %s: %w", dk.ID, err)
		}
		if ok {
			n++
		}
	}
	return n, nil
}

// active is the data key new values are sealed with: the active one, or a new one when there is none, it
// is older than maxAge, or the KEK has a new version.
func (e *Envelope) active(ctx context.Context) (string, cipher.AEAD, error) {
	for range 3 {
		dk, slot, err := e.keys.Active(ctx)
		if err != nil && !errors.Is(err, ErrNoDataKey) {
			return "", nil, err
		}
		if err == nil {
			current, err := e.wrapper.Current(ctx)
			if err != nil {
				return "", nil, fmt.Errorf("the KEK: %w", err)
			}
			if dk.KEKID == current && e.now().Sub(dk.CreatedAt) < e.maxAge {
				aead, err := e.aead(ctx, dk.ID)
				return dk.ID, aead, err
			}
		}
		id, aead, err := e.rotate(ctx, slot)
		if errors.Is(err, ErrKeyRace) {
			continue // another replica made one first: take it
		}
		return id, aead, err
	}
	return "", nil, ErrKeyRace
}

// rotate makes a new data key, wraps it and makes it the active one.
func (e *Envelope) rotate(ctx context.Context, slot int64) (string, cipher.AEAD, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return "", nil, err
	}
	wrapped, kekID, err := e.wrapper.Wrap(ctx, dek)
	if err != nil {
		return "", nil, fmt.Errorf("the KEK does not wrap: %w", err)
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	dk := DataKey{ID: hex.EncodeToString(raw), KEKID: kekID, Wrapped: wrapped, CreatedAt: e.now().UTC()}
	if err := e.keys.Activate(ctx, dk, slot); err != nil {
		return "", nil, err
	}
	aead, err := newAEAD(dek)
	if err != nil {
		return "", nil, err
	}
	e.remember(dk.ID, aead)
	return dk.ID, aead, nil
}

// aead is a data key's cipher: from the cache, or unwrapped now.
func (e *Envelope) aead(ctx context.Context, id string) (cipher.AEAD, error) {
	e.mu.Lock()
	c, ok := e.cache[id]
	e.mu.Unlock()
	if ok && e.now().Before(c.expires) {
		return c.aead, nil
	}
	dk, err := e.keys.Get(ctx, id)
	if errors.Is(err, ErrNoDataKey) {
		return nil, fmt.Errorf("%w: data key %s is not stored", ErrSealed, id)
	}
	if err != nil {
		return nil, err
	}
	dek, err := e.wrapper.Unwrap(ctx, dk.Wrapped, dk.KEKID)
	if err != nil {
		// the KEK may be unreachable: not ErrSealed - the value is not known to be bad
		return nil, fmt.Errorf("data key %s does not unwrap: %w", id, err)
	}
	aead, err := newAEAD(dek)
	clear(dek)
	if err != nil {
		return nil, err
	}
	e.remember(id, aead)
	return aead, nil
}

func (e *Envelope) remember(id string, aead cipher.AEAD) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	for k, c := range e.cache {
		if !now.Before(c.expires) {
			delete(e.cache, k)
		}
	}
	e.cache[id] = cached{aead: aead, expires: now.Add(e.ttl)}
}

func newAEAD(dek []byte) (cipher.AEAD, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("a data key must be 32 bytes, not %d", len(dek))
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
