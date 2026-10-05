package keys

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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
	cache map[string]cached     // data key id -> unwrapped
	roots map[string]cachedRoot // KEK id -> root
}

type cachedRoot struct {
	root    []byte
	expires time.Time
}

type cached struct {
	aead    cipher.AEAD
	mac     []byte // the data key's MAC key (MAC)
	v1      bool   // its tag is v1 (tagV1)
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
		now: time.Now, cache: map[string]cached{}, roots: map[string]cachedRoot{}}
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

// root is the KEK's root for kekID, from the cache or computed now (one TTL with the data keys: when the service
// loses its KEK rights, it stops within it).
func (e *Envelope) root(ctx context.Context, kekID string) ([]byte, error) {
	e.mu.Lock()
	c, ok := e.roots[kekID]
	e.mu.Unlock()
	if ok && e.now().Before(c.expires) {
		return c.root, nil
	}
	root, err := e.wrapper.Root(ctx, kekID)
	if err != nil {
		return nil, fmt.Errorf("the KEK's root: %w", err)
	}
	e.mu.Lock()
	e.roots[kekID] = cachedRoot{root: root, expires: e.now().Add(e.ttl)}
	e.mu.Unlock()
	return root, nil
}

// Tag authenticates a data key under the root of the KEK version that wrapped it: its id, its KEK id, its
// creation time (to the microsecond, as every store keeps it) and its wrapped bytes. The creation time decides
// when the key is replaced: a writer of the store must not keep one active for ever.
func Tag(root []byte, id, kekID string, wrapped []byte, created time.Time) []byte {
	m := hmac.New(sha256.New, root)
	m.Write([]byte("tresor-server/data-key/2\x00" + id + "\x00" + kekID + "\x00"))
	m.Write(binary.BigEndian.AppendUint64(nil, uint64(created.UnixMicro())))
	m.Write(wrapped)
	return m.Sum(nil)
}

// tagV1 is the tag before the creation time was in it (spec 003, a0): a data key it authenticates still opens,
// but is never the active one - its age is not authenticated - and rewrap tags it anew.
func tagV1(root []byte, id, kekID string, wrapped []byte) []byte {
	m := hmac.New(sha256.New, root)
	m.Write([]byte("tresor-server/data-key/1\x00" + id + "\x00" + kekID + "\x00"))
	m.Write(wrapped)
	return m.Sum(nil)
}

// authentic checks a stored data key's tag: one planted by whoever could write the store - wrapped with an RSA
// KEK's public key, say - has none that matches (ErrSealed). A KEK that does not answer is not ErrSealed. v1: the
// tag is the former one, which does not cover the creation time.
func (e *Envelope) authentic(ctx context.Context, dk DataKey) (v1 bool, err error) {
	if len(dk.Tag) == 0 {
		return false, fmt.Errorf("%w: data key %s has no tag (made before spec 003: tresor-server rewrap tags it)", ErrSealed, dk.ID)
	}
	root, err := e.root(ctx, dk.KEKID)
	if err != nil {
		return false, err
	}
	switch {
	case hmac.Equal(dk.Tag, Tag(root, dk.ID, dk.KEKID, dk.Wrapped, dk.CreatedAt)):
		return false, nil
	case hmac.Equal(dk.Tag, tagV1(root, dk.ID, dk.KEKID, dk.Wrapped)):
		return true, nil
	}
	return false, fmt.Errorf("%w: data key %s is not authentic", ErrSealed, dk.ID)
}

// Check wraps and unwraps a throwaway key, and computes the current root: the KEK answers (readiness).
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
	if _, err := e.wrapper.Root(ctx, kekID); err != nil {
		return fmt.Errorf("the KEK does not give its root (sign): %w", err)
	}
	return nil
}

// Rewrap wraps every data key under the KEK's current version, where it is not already, and tags it: after a
// rotation of the KEK its old versions can be retired. A data key whose tag does not match is never rewrapped.
// A data key with no tag (made before spec 003) is tagged only when tagUntagged says so - once, at the upgrade,
// the operator vouching for the store as it is; otherwise it is skipped and named, for a key planted since
// would carry no tag either. The values sealed under the data keys are not touched. It goes on past a data key
// it cannot rewrap: how many were rewrapped, and an error naming each one skipped. tagged names each data key
// it tagged from none.
func (e *Envelope) Rewrap(ctx context.Context, tagUntagged bool, tagged func(id string)) (int, error) {
	current, err := e.wrapper.Current(ctx)
	if err != nil {
		return 0, fmt.Errorf("the KEK: %w", err)
	}
	all, err := e.keys.List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	var skipped []error
	for _, dk := range all {
		untagged := len(dk.Tag) == 0
		switch {
		case untagged && !tagUntagged:
			skipped = append(skipped, fmt.Errorf("data key %s has no tag: not tagged without --tag-untagged", dk.ID))
			continue
		case !untagged:
			v1, err := e.authentic(ctx, dk)
			if err != nil {
				skipped = append(skipped, fmt.Errorf("data key %s: %w", dk.ID, err))
				continue
			}
			if dk.KEKID == current && !v1 {
				continue
			}
		}
		ok, err := e.rewrapOne(ctx, dk, current)
		if err != nil {
			skipped = append(skipped, fmt.Errorf("data key %s (under %s): %w", dk.ID, dk.KEKID, err))
			continue
		}
		if ok {
			n++
			if untagged && tagged != nil {
				tagged(dk.ID)
			}
		}
	}
	if len(skipped) > 0 {
		return n, fmt.Errorf("%d data keys were not rewrapped: %w", len(skipped), errors.Join(skipped...))
	}
	return n, nil
}

func (e *Envelope) rewrapOne(ctx context.Context, dk DataKey, current string) (bool, error) {
	dek, err := e.wrapper.Unwrap(ctx, dk.Wrapped, dk.KEKID)
	if err != nil {
		return false, err
	}
	if len(dek) != 32 {
		clear(dek)
		return false, fmt.Errorf("%w: data key %s unwraps to %d bytes, not 32", ErrSealed, dk.ID, len(dek))
	}
	wrapped, kekID := dk.Wrapped, dk.KEKID
	if dk.KEKID != current {
		wrapped, kekID, err = e.wrapper.Wrap(ctx, dek)
	}
	clear(dek)
	if err != nil {
		return false, err
	}
	root, err := e.root(ctx, kekID)
	if err != nil {
		return false, err
	}
	return e.keys.Rewrapped(ctx, dk.ID, dk.KEKID, wrapped, kekID, Tag(root, dk.ID, kekID, wrapped, dk.CreatedAt))
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
				c, err := e.key(ctx, dk.ID)
				if err != nil {
					return "", nil, err
				}
				if !c.v1 { // a v1 tag does not vouch for the key's age: replaced
					return dk.ID, c.aead, nil
				}
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
	defer clear(dek)
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
	dk := DataKey{ID: hex.EncodeToString(raw), KEKID: kekID, Wrapped: wrapped, CreatedAt: e.now().UTC().Truncate(time.Microsecond)}
	root, err := e.root(ctx, kekID)
	if err != nil {
		return "", nil, err
	}
	dk.Tag = Tag(root, dk.ID, dk.KEKID, dk.Wrapped, dk.CreatedAt)
	if err := e.keys.Activate(ctx, dk, slot); err != nil {
		return "", nil, err
	}
	c, err := newKey(dek)
	if err != nil {
		return "", nil, err
	}
	return dk.ID, e.remember(dk.ID, c).aead, nil
}

// aead is a data key's cipher: from the cache, or unwrapped now.
func (e *Envelope) aead(ctx context.Context, id string) (cipher.AEAD, error) {
	c, err := e.key(ctx, id)
	return c.aead, err
}

// key is a data key, unwrapped: from the cache, or unwrapped now.
func (e *Envelope) key(ctx context.Context, id string) (cached, error) {
	e.mu.Lock()
	c, ok := e.cache[id]
	e.mu.Unlock()
	if ok && e.now().Before(c.expires) {
		return c, nil
	}
	dk, err := e.keys.Get(ctx, id)
	if errors.Is(err, ErrNoDataKey) {
		return cached{}, fmt.Errorf("%w: data key %s is not stored", ErrSealed, id)
	}
	if err != nil {
		return cached{}, err
	}
	v1, err := e.authentic(ctx, dk)
	if err != nil {
		return cached{}, err
	}
	dek, err := e.wrapper.Unwrap(ctx, dk.Wrapped, dk.KEKID)
	if err != nil {
		// the KEK may be unreachable: not ErrSealed - the value is not known to be bad
		return cached{}, fmt.Errorf("data key %s does not unwrap: %w", id, err)
	}
	c, err = newKey(dek)
	clear(dek)
	if err != nil {
		return cached{}, err
	}
	c.v1 = v1
	return e.remember(id, c), nil
}

func (e *Envelope) remember(id string, c cached) cached {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	for k, old := range e.cache {
		if !now.Before(old.expires) {
			delete(e.cache, k)
		}
	}
	c.expires = now.Add(e.ttl)
	e.cache[id] = c
	return c
}

// newKey is an unwrapped data key's cipher, and its MAC key: HMAC-SHA256 under the data key of a fixed label.
func newKey(dek []byte) (cached, error) {
	if len(dek) != 32 {
		return cached{}, fmt.Errorf("a data key must be 32 bytes, not %d", len(dek))
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return cached{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return cached{}, err
	}
	m := hmac.New(sha256.New, dek)
	m.Write([]byte("tresor-server/mac-key/1"))
	return cached{aead: aead, mac: m.Sum(nil)}, nil
}

// Current names the KEK's current version (the console's service page, spec 010): the wrapper's answer.
func (e *Envelope) Current(ctx context.Context) (string, error) { return e.wrapper.Current(ctx) }

// ActiveID names the data key new values are sealed with - made now if there is none: what a value with
// nothing sealed is authenticated under (MAC).
func (e *Envelope) ActiveID(ctx context.Context) (string, error) {
	id, _, err := e.active(ctx)
	return id, err
}

// MAC authenticates msg under the data key id names (spec 003): HMAC-SHA256 under a key derived from the data
// key. The data key is authenticated by the KEK's root, so only the KEK's holder can make a MAC that verifies;
// a rewrap keeps the data key, and so every MAC made under it.
func (e *Envelope) MAC(ctx context.Context, dataKeyID string, msg []byte) ([]byte, error) {
	c, err := e.key(ctx, dataKeyID)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, c.mac)
	m.Write(msg)
	return m.Sum(nil), nil
}

// Verify checks a MAC made by MAC: one that does not match is ErrSealed; a KEK that does not answer is not.
func (e *Envelope) Verify(ctx context.Context, dataKeyID string, msg, mac []byte) error {
	want, err := e.MAC(ctx, dataKeyID, msg)
	if err != nil {
		return err
	}
	if !hmac.Equal(mac, want) {
		return fmt.Errorf("%w: its MAC does not match", ErrSealed)
	}
	return nil
}
