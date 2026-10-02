package vaultkek

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/vault"
	"github.com/hugr-lab/tresor-server/internal/vault/vaulttest"
)

var ctx = context.Background()

// store is a DataKeyStore in memory, compare-and-set as a real one
type store struct {
	mu     sync.Mutex
	keys   map[string]keys.DataKey
	active string
	slot   int64
}

func (s *store) Get(_ context.Context, id string) (keys.DataKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dk, ok := s.keys[id]
	if !ok {
		return keys.DataKey{}, keys.ErrNoDataKey
	}
	return dk, nil
}
func (s *store) Active(c context.Context) (keys.DataKey, int64, error) {
	s.mu.Lock()
	id, slot := s.active, s.slot
	s.mu.Unlock()
	if id == "" {
		return keys.DataKey{}, 0, keys.ErrNoDataKey
	}
	dk, err := s.Get(c, id)
	return dk, slot, err
}
func (s *store) Activate(_ context.Context, dk keys.DataKey, slot int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slot != s.slot {
		return keys.ErrKeyRace
	}
	s.keys[dk.ID], s.active, s.slot = dk, dk.ID, s.slot+1
	return nil
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

// the KEK in Transit, on every server given: seal and open, a rotation and a rewrap, the root per version,
// a planted data key refused, a retired version sealed
func TestTransit(t *testing.T) {
	for _, srv := range vaulttest.Servers(t) {
		t.Run(srv.Name, func(t *testing.T) {
			mount := srv.Mount(t, "transit")
			srv.Call(t, "POST", mount+"/keys/kek", map[string]any{"type": "aes256-gcm96"}, nil)
			client, err := vault.New(vault.Config{Address: srv.Address, Auth: vault.Auth{Method: "token_file", TokenFile: srv.TokenFile(t)}})
			if err != nil {
				t.Fatal(err)
			}
			w, err := New(client, mount, "kek")
			if err != nil {
				t.Fatal(err)
			}
			st := &store{keys: map[string]keys.DataKey{}}
			env := keys.NewEnvelope(w, st, keys.Options{})
			if err := env.Check(ctx); err != nil {
				t.Fatalf("the KEK's check: %v", err)
			}
			id1, sealed, err := env.Seal(ctx, []byte("aad"), []byte("material"))
			if err != nil {
				t.Fatal(err)
			}
			if st.keys[id1].KEKID != "vault:"+mount+"/kek:v1" {
				t.Fatalf("the KEK id: %s", st.keys[id1].KEKID)
			}
			// another replica, cold: unwraps and authenticates through Vault
			if plain, err := keys.NewEnvelope(w, st, keys.Options{}).Open(ctx, id1, []byte("aad"), sealed); err != nil || string(plain) != "material" {
				t.Fatalf("open: %q %v", plain, err)
			}
			r1, _ := w.Root(ctx, "vault:"+mount+"/kek:v1")
			if r1again, _ := w.Root(ctx, "vault:"+mount+"/kek:v1"); string(r1) != string(r1again) || len(r1) != 32 {
				t.Fatal("the root is not deterministic")
			}
			// a rotation: new data keys under v2, the old value still opens, its root another
			srv.Call(t, "POST", mount+"/keys/kek/rotate", nil, nil)
			w.mu.Lock()
			w.readAt = time.Time{}
			w.mu.Unlock()
			if cur, _ := w.Current(ctx); cur != "vault:"+mount+"/kek:v2" {
				t.Fatalf("current after rotation: %s", cur)
			}
			if r2, _ := w.Root(ctx, "vault:"+mount+"/kek:v2"); string(r2) == string(r1) {
				t.Fatal("one root for two versions")
			}
			if n, err := keys.NewEnvelope(w, st, keys.Options{}).Rewrap(ctx, false, nil); err != nil || n != 1 {
				t.Fatalf("rewrap: %d %v", n, err)
			}
			if st.keys[id1].KEKID != "vault:"+mount+"/kek:v2" {
				t.Fatalf("after rewrap: %s", st.keys[id1].KEKID)
			}
			// v1 retired: nothing depends on it after the rewrap
			srv.Call(t, "POST", mount+"/keys/kek/config", map[string]any{"min_decryption_version": 2}, nil)
			if plain, err := keys.NewEnvelope(w, st, keys.Options{}).Open(ctx, id1, []byte("aad"), sealed); err != nil || string(plain) != "material" {
				t.Fatalf("open after rewrap and retirement: %v", err)
			}
			// a data key from before the retirement, still under v1: sealed, not an outage
			v1, err := w.Unwrap(ctx, []byte("vault:v1:AAAA"), "vault:"+mount+"/kek:v1")
			if !errors.Is(err, keys.ErrSealed) || v1 != nil {
				t.Fatalf("a retired version: %v", err)
			}
			// a planted data key, wrapped by whoever may encrypt with the key but holds no HMAC right: no tag
			planted, kekID, _ := w.Wrap(ctx, make([]byte, 32))
			st.mu.Lock()
			st.keys["planted"] = keys.DataKey{ID: "planted", KEKID: kekID, Wrapped: planted, Tag: make([]byte, 32), CreatedAt: time.Now()}
			st.mu.Unlock()
			if _, err := keys.NewEnvelope(w, st, keys.Options{}).Open(ctx, "planted", nil, sealed); !errors.Is(err, keys.ErrSealed) {
				t.Fatalf("a planted data key: %v", err)
			}
			// another key's KEK id, or a ciphertext of another version: sealed
			if _, err := w.Unwrap(ctx, planted, "vault:"+mount+"/other:v2"); !errors.Is(err, keys.ErrSealed) {
				t.Fatalf("another key's id: %v", err)
			}
			if _, err := w.Unwrap(ctx, planted, "vault:"+mount+"/kek:v1"); !errors.Is(err, keys.ErrSealed) {
				t.Fatalf("a version that is not the ciphertext's: %v", err)
			}
		})
	}
}

// Vault that does not answer: no verdict, never ErrSealed
func TestDown(t *testing.T) {
	client, err := vault.New(vault.Config{Address: "http://127.0.0.1:1", Auth: vault.Auth{Method: "token_file", TokenFile: writeToken(t)}})
	if err != nil {
		t.Fatal(err)
	}
	w, _ := New(client, "transit", "kek")
	if _, err := w.Unwrap(ctx, []byte("vault:v1:AAAA"), "vault:transit/kek:v1"); err == nil || errors.Is(err, keys.ErrSealed) {
		t.Fatalf("Vault down: %v", err)
	}
	if _, err := w.Root(ctx, "vault:transit/kek:v1"); err == nil || errors.Is(err, keys.ErrSealed) {
		t.Fatalf("Vault down, the root: %v", err)
	}
}

func writeToken(t *testing.T) string {
	t.Helper()
	p := t.TempDir() + "/token"
	if err := os.WriteFile(p, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
