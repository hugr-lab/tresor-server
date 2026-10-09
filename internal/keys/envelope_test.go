package keys_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/keys/local"
)

// store is a DataKeyStore in memory, with the compare-and-set of a real one.
type store struct {
	mu     sync.Mutex
	keys   map[string]keys.DataKey
	active string
	slot   int64
}

func newStore() *store { return &store{keys: map[string]keys.DataKey{}} }

func (s *store) Get(_ context.Context, id string) (keys.DataKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dk, ok := s.keys[id]
	if !ok {
		return keys.DataKey{}, keys.ErrNoDataKey
	}
	return dk, nil
}

func (s *store) Active(ctx context.Context) (keys.DataKey, int64, error) {
	s.mu.Lock()
	id, slot := s.active, s.slot
	s.mu.Unlock()
	if id == "" {
		return keys.DataKey{}, 0, keys.ErrNoDataKey
	}
	dk, err := s.Get(ctx, id)
	return dk, slot, err
}

func (s *store) Activate(_ context.Context, dk keys.DataKey, slot int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slot != s.slot {
		return keys.ErrKeyRace
	}
	s.keys[dk.ID] = dk
	s.active, s.slot = dk.ID, s.slot+1
	return nil
}

func wrapper(t *testing.T, b byte) keys.KeyWrapper {
	t.Helper()
	w, err := local.New(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

var ctx = context.Background()

// unreachable is a KEK that does not answer (a KMS outage).
type unreachable struct{}

func (unreachable) Wrap(context.Context, []byte) ([]byte, string, error) {
	return nil, "", errors.New("timeout")
}
func (unreachable) Unwrap(context.Context, []byte, string) ([]byte, error) {
	return nil, errors.New("timeout")
}
func (unreachable) Current(context.Context) (string, error)      { return "", errors.New("timeout") }
func (unreachable) Root(context.Context, string) ([]byte, error) { return nil, errors.New("timeout") }
func (unreachable) Owns(string) bool                             { return true }

func TestSealOpen(t *testing.T) {
	st := newStore()
	e := keys.NewEnvelope(wrapper(t, 1), st, keys.Options{})
	id, sealed, err := e.Seal(ctx, []byte("aad"), []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("hunter2")) {
		t.Fatal("sealed holds the plain text")
	}
	if plain, err := e.Open(ctx, id, []byte("aad"), sealed); err != nil || string(plain) != "hunter2" {
		t.Fatalf("open: %q %v", plain, err)
	}
	// a second value under the same data key
	if id2, _, _ := e.Seal(ctx, []byte("aad"), []byte("x")); id2 != id {
		t.Fatal("a data key per value: want one active key")
	}
	// another aad (another row, name or version), a flipped byte, an unknown key: never opens
	if _, err := e.Open(ctx, id, []byte("other"), sealed); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("another aad: %v", err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := e.Open(ctx, id, []byte("aad"), sealed); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("a tampered value: %v", err)
	}
	if _, err := e.Open(ctx, "missing", []byte("aad"), sealed); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("an unknown data key: %v", err)
	}
	// a fresh envelope (another replica, a restart) unwraps the stored key
	other := keys.NewEnvelope(wrapper(t, 1), st, keys.Options{})
	sealed[len(sealed)-1] ^= 1
	if plain, err := other.Open(ctx, id, []byte("aad"), sealed); err != nil || string(plain) != "hunter2" {
		t.Fatalf("another replica: %v", err)
	}
	// under another KEK the data key never unwraps: ErrSealed (not transient)
	wrong := keys.NewEnvelope(wrapper(t, 2), st, keys.Options{})
	if _, err := wrong.Open(ctx, id, []byte("aad"), sealed); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("another KEK: %v", err)
	}
	// a KEK that cannot be reached is not ErrSealed: nothing is known to be bad
	down := keys.NewEnvelope(unreachable{}, st, keys.Options{})
	if _, err := down.Open(ctx, id, []byte("aad"), sealed); err == nil || errors.Is(err, keys.ErrSealed) {
		t.Fatalf("an unreachable KEK: %v", err)
	}
	if err := e.Check(ctx); err != nil {
		t.Fatal(err)
	}
}

// a data key older than the maximum age is replaced for new values; old values still open
func TestRotation(t *testing.T) {
	st := newStore()
	e := keys.NewEnvelope(wrapper(t, 1), st, keys.Options{DataKeyMaxAge: time.Hour})
	first, sealed, _ := e.Seal(ctx, nil, []byte("old"))
	later := keys.NewEnvelope(wrapper(t, 1), st, keys.Options{DataKeyMaxAge: time.Nanosecond})
	time.Sleep(time.Millisecond)
	second, _, err := later.Seal(ctx, nil, []byte("new"))
	if err != nil || second == first {
		t.Fatalf("no new data key: %s %v", second, err)
	}
	if plain, err := later.Open(ctx, first, nil, sealed); err != nil || string(plain) != "old" {
		t.Fatalf("an old value after rotation: %v", err)
	}
}

// replicas making the first data key at once: one wins, everyone seals under it
func TestActivationRace(t *testing.T) {
	st := newStore()
	ids := make([]string, 8)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := keys.NewEnvelope(wrapper(t, 1), st, keys.Options{})
			id, _, err := e.Seal(ctx, nil, []byte("x"))
			if err != nil {
				t.Error(err)
			}
			ids[i] = id
		}()
	}
	wg.Wait()
	for _, id := range ids {
		if _, err := st.Get(ctx, id); err != nil {
			t.Fatalf("sealed under a data key that is not stored: %s", id)
		}
	}
}

func (s *store) List(context.Context) ([]keys.DataKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []keys.DataKey
	for _, dk := range s.keys {
		out = append(out, dk)
	}
	return out, nil
}

func (s *store) Rewrapped(_ context.Context, id, from string, wrapped []byte, kekID string, tag []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dk, ok := s.keys[id]
	if !ok || dk.KEKID != from {
		return false, nil
	}
	dk.Wrapped, dk.KEKID, dk.Tag = wrapped, kekID, tag
	s.keys[id] = dk
	return true, nil
}

// a MAC verifies under its data key - from another envelope, as another replica - and nothing else does
func TestMAC(t *testing.T) {
	st := newStore()
	e := keys.NewEnvelope(wrapper(t, 1), st, keys.Options{})
	id, err := e.ActiveID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := e.MAC(ctx, id, []byte("resource"))
	if err != nil {
		t.Fatal(err)
	}
	other := keys.NewEnvelope(wrapper(t, 1), st, keys.Options{})
	if err := other.Verify(ctx, id, []byte("resource"), mac); err != nil {
		t.Fatalf("another replica: %v", err)
	}
	if err := other.Verify(ctx, id, []byte("resourcf"), mac); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("a changed message: %v", err)
	}
	if err := other.Verify(ctx, "0000", []byte("resource"), mac); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("a data key that is not stored: %v", err)
	}
	// another KEK's MAC key is another: a resource from an installation with another KEK does not verify
	if err := keys.NewEnvelope(wrapper(t, 2), st, keys.Options{}).Verify(ctx, id, []byte("resource"), mac); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("under another KEK: %v", err)
	}
	// a KEK that does not answer is no forgery
	if err := keys.NewEnvelope(unreachable{}, st, keys.Options{}).Verify(ctx, id, []byte("resource"), mac); err == nil || errors.Is(err, keys.ErrSealed) {
		t.Fatalf("an unreachable KEK: %v", err)
	}
}

// a data key's creation time is in its tag: moved forward to keep it active for ever, it is not authentic
func TestCreationTimeAuthenticated(t *testing.T) {
	st := newStore()
	e := keys.NewEnvelope(wrapper(t, 1), st, keys.Options{})
	id, sealed, err := e.Seal(ctx, nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	dk := st.keys[id]
	dk.CreatedAt = dk.CreatedAt.Add(10 * 365 * 24 * time.Hour)
	st.keys[id] = dk
	if _, err := keys.NewEnvelope(wrapper(t, 1), st, keys.Options{}).Open(ctx, id, nil, sealed); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("a creation time moved: %v", err)
	}
}

// a data key tagged before the creation time was in the tag (v1) still opens, is never the active one, and
// rewrap tags it anew
func TestTagV1(t *testing.T) {
	st := newStore()
	w := wrapper(t, 1)
	e := keys.NewEnvelope(w, st, keys.Options{})
	id, sealed, err := e.Seal(ctx, nil, []byte("old"))
	if err != nil {
		t.Fatal(err)
	}
	dk := st.keys[id]
	root, err := w.Root(ctx, dk.KEKID)
	if err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, root)
	m.Write([]byte("tresor-server/data-key/1\x00" + dk.ID + "\x00" + dk.KEKID + "\x00"))
	m.Write(dk.Wrapped)
	dk.Tag = m.Sum(nil)
	st.keys[id] = dk
	fresh := keys.NewEnvelope(w, st, keys.Options{})
	if plain, err := fresh.Open(ctx, id, nil, sealed); err != nil || string(plain) != "old" {
		t.Fatalf("a v1 data key: %v", err)
	}
	if next, _, err := fresh.Seal(ctx, nil, []byte("new")); err != nil || next == id {
		t.Fatalf("a v1 data key stays active: %s %v", next, err)
	}
	if n, err := keys.NewEnvelope(w, st, keys.Options{}).Rewrap(ctx, false, nil); err != nil || n != 1 {
		t.Fatalf("rewrap: %d %v", n, err)
	}
	if n, err := keys.NewEnvelope(w, st, keys.Options{}).Rewrap(ctx, false, nil); err != nil || n != 0 {
		t.Fatalf("a second rewrap: %d %v", n, err)
	}
	if plain, err := keys.NewEnvelope(w, st, keys.Options{}).Open(ctx, id, nil, sealed); err != nil || string(plain) != "old" {
		t.Fatalf("after rewrap: %v", err)
	}
}

func (s *store) Delete(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[id]; !ok || id == s.active {
		return false, nil
	}
	delete(s.keys, id)
	return true, nil
}
