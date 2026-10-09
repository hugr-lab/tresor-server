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

// the root is Vault's alone: a token that may encrypt but not HMAC computes none; a tag under another key's HMAC
// is not this key's; a key that can be exported, or whose min_encryption_version refuses the root, is refused;
// a replica that read an older version learns of a rotation at its next wrap
func TestRootIsTheHolders(t *testing.T) {
	for _, srv := range vaulttest.Servers(t) {
		t.Run(srv.Name, func(t *testing.T) {
			mount := srv.Mount(t, "transit")
			for _, k := range []string{"kek", "other"} {
				srv.Call(t, "POST", mount+"/keys/"+k, map[string]any{"type": "aes256-gcm96"}, nil)
			}
			root := func(c *vault.Client, key string) ([]byte, error) {
				w, _ := New(c, mount, key)
				return w.Root(ctx, "vault:"+mount+"/"+key+":v1")
			}
			rootClient, _ := vault.New(vault.Config{Address: srv.Address, Auth: vault.Auth{Method: "token_file", TokenFile: srv.TokenFile(t)}})
			r, err := root(rootClient, "kek")
			if err != nil {
				t.Fatal(err)
			}
			if other, _ := root(rootClient, "other"); string(other) == string(r) {
				t.Fatal("two keys, one root")
			}
			// an encrypt-only token: it wraps, it computes no root - and its refusal is no verdict on a value
			srv.Call(t, "PUT", "sys/policies/acl/"+mount+"-enc", map[string]any{"policy": `path "` + mount + `/encrypt/kek" { capabilities = ["update"] }`}, nil)
			var tok struct {
				Auth struct {
					ClientToken string `json:"client_token"`
				} `json:"auth"`
			}
			srv.Call(t, "POST", "auth/token/create", map[string]any{"policies": []string{mount + "-enc"}, "no_default_policy": true}, &tok)
			tf := t.TempDir() + "/enc"
			_ = os.WriteFile(tf, []byte(tok.Auth.ClientToken), 0o600)
			enc, _ := vault.New(vault.Config{Address: srv.Address, Auth: vault.Auth{Method: "token_file", TokenFile: tf}})
			w, _ := New(enc, mount, "kek")
			if _, _, err := w.Wrap(ctx, make([]byte, 32)); err != nil {
				t.Fatalf("encrypt-only wraps: %v", err)
			}
			if _, err := w.Root(ctx, "vault:"+mount+"/kek:v1"); err == nil || errors.Is(err, keys.ErrSealed) {
				t.Fatalf("encrypt-only computed a root, or was called sealed: %v", err)
			}
			// a version above the latest: no such root, for good
			if _, err := root(rootClient, "kek"); err != nil {
				t.Fatal(err)
			}
			wk, _ := New(rootClient, mount, "kek")
			if _, err := wk.Root(ctx, "vault:"+mount+"/kek:v9"); !errors.Is(err, keys.ErrSealed) {
				t.Fatalf("a version never made: %v", err)
			}
			// a stale replica: it read v1, the key rotates, its next wrap is v2 and its current follows
			if cur, _ := wk.Current(ctx); cur != "vault:"+mount+"/kek:v1" {
				t.Fatal(cur)
			}
			srv.Call(t, "POST", mount+"/keys/kek/rotate", nil, nil)
			if _, id, _ := wk.Wrap(ctx, make([]byte, 32)); id != "vault:"+mount+"/kek:v2" {
				t.Fatalf("wrapped under %s", id)
			}
			if cur, _ := wk.Current(ctx); cur != "vault:"+mount+"/kek:v2" {
				t.Fatalf("current after a wrap under v2: %s", cur)
			}
			// keys whose root is not Vault's alone, or not computable
			srv.Call(t, "POST", mount+"/keys/exportable", map[string]any{"type": "aes256-gcm96", "exportable": true}, nil)
			srv.Call(t, "POST", mount+"/keys/minenc", map[string]any{"type": "aes256-gcm96"}, nil)
			srv.Call(t, "POST", mount+"/keys/minenc/rotate", nil, nil)
			srv.Call(t, "POST", mount+"/keys/minenc/config", map[string]any{"min_encryption_version": 2}, nil)
			for _, k := range []string{"exportable", "minenc"} {
				w, _ := New(rootClient, mount, k)
				if _, err := w.Current(ctx); err == nil {
					t.Errorf("%s: accepted as a KEK", k)
				}
			}
		})
	}
}

// Owns (spec 011): every version of this mount's key, nothing else
func TestOwns(t *testing.T) {
	w, err := New(nil, "transit", "kek")
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{
		"vault:transit/kek:v1": true, "vault:transit/kek:v12": true,
		"vault:transit/kek:v0": false, "vault:transit/kek:v01": false, "vault:transit/kek2:v1": false,
		"vault:other/kek:v1": false, "local:00": false, "": false,
	} {
		if w.Owns(id) != want {
			t.Errorf("%q: %v", id, !want)
		}
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
