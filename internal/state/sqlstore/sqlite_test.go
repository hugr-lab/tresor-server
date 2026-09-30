package sqlstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/keys/local"
	"github.com/hugr-lab/tresor-server/internal/state"
	"github.com/hugr-lab/tresor-server/internal/state/statetest"
)

var ctx = context.Background()

func kek(t *testing.T, b byte) keys.KeyWrapper {
	t.Helper()
	w, err := local.New(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func openAt(t *testing.T, path string, w keys.KeyWrapper) *Store {
	t.Helper()
	s, err := OpenSQLite(ctx, path, w, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSQLite(t *testing.T) {
	statetest.Run(t, func(t *testing.T) statetest.Handles {
		path := filepath.Join(t.TempDir(), "tresor.db")
		first := openAt(t, path, kek(t, 1))
		return statetest.Handles{First: first, Another: func() state.Store {
			first.Close() // one writer: another handle is a restart
			return openAt(t, path, kek(t, 1))
		}}
	})
}

func put(t *testing.T, s *Store, name, secret string) {
	t.Helper()
	_, err := s.Update(ctx, name, func(*state.Secret) (*state.Secret, error) {
		return &state.Secret{Type: "s3", Version: 1,
			Params: map[string]json.RawMessage{"secret": json.RawMessage(`"` + secret + `"`)}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// the params are sealed at rest: the database file holds no material
func TestSealedAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tresor.db")
	s := openAt(t, path, kek(t, 1))
	put(t, s, "lake", "hunter2-material")
	s.Close()
	for _, f := range []string{path, path + "-wal"} {
		data, err := os.ReadFile(f)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("hunter2-material")) {
			t.Fatalf("%s holds the material", filepath.Base(f))
		}
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("the database is %v, want 0600", info.Mode().Perm())
	}
}

// a sealed value that does not open - tampered, moved to another name, under another KEK - is an error for
// that secret, never an empty value; the list still answers
func TestSealedFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tresor.db")
	s := openAt(t, path, kek(t, 1))
	put(t, s, "a", "one")
	put(t, s, "b", "two")
	// b's sealed params copied onto a: the AAD names another row and name
	if _, err := s.db.Exec(`UPDATE secrets SET sealed = (SELECT sealed FROM secrets WHERE name = 'b'),
		data_key_id = (SELECT data_key_id FROM secrets WHERE name = 'b') WHERE name = 'a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "a"); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("moved params: %v", err)
	}
	if _, err := s.Update(ctx, "a", func(cur *state.Secret) (*state.Secret, error) {
		cur.Version++
		return cur, nil
	}); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("a secret that does not open is rewritten: %v", err)
	}
	if list, err := s.List(ctx); err != nil || len(list) != 2 {
		t.Fatalf("the list: %v", err)
	}
	if d, err := s.Describe(ctx, "a"); err != nil || d.Params != nil || d.Version != 1 {
		t.Fatalf("a descriptor opens no material, so a broken one still answers: %v", err)
	}
	// an admin may delete it: nothing that opens is lost
	if _, err := s.Update(ctx, "a", func(cur *state.Secret) (*state.Secret, error) {
		if cur == nil || cur.Params != nil {
			t.Fatalf("fn got %+v: the descriptor, no params", cur)
		}
		return nil, nil
	}); err != nil {
		t.Fatalf("deleting a secret that does not open: %v", err)
	}
	if _, err := s.Get(ctx, "a"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("after the delete: %v", err)
	}
	s.Close()
	other := openAt(t, path, kek(t, 2))
	if _, err := other.Get(ctx, "b"); err == nil {
		t.Fatal("params open under another KEK")
	}
}

// one replica serves a SQLite database: another waits, serving nothing, and takes over when the first stops
func TestLease(t *testing.T) {
	shortLease(t)
	path := filepath.Join(t.TempDir(), "tresor.db")
	first := openAt(t, path, kek(t, 1))
	put(t, first, "a", "x")
	second := openAt(t, path, kek(t, 1))
	if _, err := second.List(ctx); !errors.Is(err, state.ErrUnavailable) {
		t.Fatalf("a second replica serves: %v", err)
	}
	if err := second.Ping(ctx); err == nil || !strings.Contains(err.Error(), "lease") {
		t.Fatalf("a second replica is ready: %v", err)
	}
	if err := first.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	first.Close() // frees the lease
	deadline := time.Now().Add(3 * time.Second)
	for second.Ping(ctx) != nil && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got, err := second.Get(ctx, "a"); err != nil || got.Version != 1 {
		t.Fatalf("the second replica after the first stopped: %v", err)
	}
}

// a database migrated by a newer binary is refused, never written
func TestNewerDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tresor.db")
	s := openAt(t, path, kek(t, 1))
	if _, err := s.db.Exec(`INSERT INTO schema_migrations (version, name, applied_at) VALUES (9999, 'future', 0)`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := OpenSQLite(ctx, path, kek(t, 1), Options{}); err == nil || !strings.Contains(err.Error(), "9999") {
		t.Fatalf("a newer database: %v", err)
	}
}

func shortLease(t *testing.T) {
	leaseTTL, leaseRenew, leaseMargin = 600*time.Millisecond, 100*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { leaseTTL, leaseRenew, leaseMargin = 15*time.Second, 5*time.Second, 5*time.Second })
}

// a secret dropped and created again starts at version 1 again: a write read before the drop must not land
// on the new one (the row id is in the compare-and-set), for an update and for a delete
func TestNoABA(t *testing.T) {
	s := openAt(t, filepath.Join(t.TempDir(), "tresor.db"), kek(t, 1))
	for _, change := range []string{"update", "delete"} {
		put(t, s, "lake", "first")
		var runs int
		s.beforeWrite = func() {
			if runs++; runs > 1 {
				return
			}
			// another replica, between this one's read and its write: drop "lake" and create it again
			s.beforeWrite = nil
			if _, err := s.Update(ctx, "lake", func(*state.Secret) (*state.Secret, error) { return nil, nil }); err != nil {
				t.Fatal(err)
			}
			put(t, s, "lake", "second")
			s.beforeWrite = func() { runs++ }
		}
		_, err := s.Update(ctx, "lake", func(cur *state.Secret) (*state.Secret, error) {
			if change == "delete" {
				return nil, nil
			}
			cur.Comment = "changed"
			cur.Version++
			return cur, nil
		})
		s.beforeWrite = nil
		if err != nil {
			t.Fatalf("%s: %v", change, err)
		}
		if runs < 2 {
			t.Fatalf("%s: fn was not run again on the new secret", change)
		}
		got, err := s.Get(ctx, "lake")
		switch {
		case change == "update" && (err != nil || got.Comment != "changed" || string(got.Params["secret"]) != `"second"`):
			t.Fatalf("the update landed on the old secret, or broke the new one: %v %+v", err, got)
		case change == "delete" && !errors.Is(err, state.ErrNotFound):
			t.Fatalf("the delete, run again on the new secret, deletes it: %v", err)
		}
		if change == "update" {
			if _, err := s.Update(ctx, "lake", func(*state.Secret) (*state.Secret, error) { return nil, nil }); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// a holder that cannot renew stops serving at its own deadline, before another may take over
func TestLeaseFencing(t *testing.T) {
	shortLease(t)
	s := openAt(t, filepath.Join(t.TempDir(), "tresor.db"), kek(t, 1))
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	s.lease.stop() // no more renewals: as a paused process
	s.lease.mu.Lock()
	s.lease.heldUntil = time.Now().Add(leaseTTL - leaseMargin)
	s.lease.mu.Unlock()
	time.Sleep(leaseTTL - leaseMargin + 50*time.Millisecond)
	if _, err := s.List(ctx); !errors.Is(err, state.ErrUnavailable) {
		t.Fatalf("serving past its deadline: %v", err)
	}
	s.lease = nil // stopped already
}

// a grant's subject token and minted tokens are sealed at rest; its id is not stored at all
func TestDelegationsSealedAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tresor.db")
	s := openAt(t, path, kek(t, 1))
	now := time.Now()
	g := state.Delegation{IDHash: []byte("hash-of-the-grant-id"), ActorOwner: "subject:i|node", ActorClient: "client:node",
		UserOwner: "subject:i|alice", User: []byte(`{}`), ExpiresAt: now.Add(time.Hour),
		Subject: []byte("hunter2-subject-token"), SubjectExpiresAt: now.Add(time.Hour)}
	if err := s.Delegations().Put(ctx, g, 10); err != nil {
		t.Fatal(err)
	}
	if err := s.Delegations().PutToken(ctx, g.IDHash, state.MintedToken{Key: "aud", Version: 1,
		Token: []byte(`{"Refresh":"hunter2-refresh-token"}`)}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	for _, f := range []string{path, path + "-wal"} {
		data, err := os.ReadFile(f)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("hunter2")) {
			t.Fatalf("%s holds a token in the clear", filepath.Base(f))
		}
	}
	// sealed to the grant: a subject token moved to another grant does not open
	s = openAt(t, path, kek(t, 1))
	other := g
	other.IDHash, other.Subject = []byte("another-grant"), nil
	if err := s.Delegations().Put(ctx, other, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE delegations SET subject_key_id = (SELECT subject_key_id FROM delegations WHERE id_hash = ?),
		subject_sealed = (SELECT subject_sealed FROM delegations WHERE id_hash = ?) WHERE id_hash = ?`,
		hexOf(g.IDHash), hexOf(g.IDHash), hexOf(other.IDHash)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Delegations().SubjectToken(ctx, other.IDHash, now); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("a subject token moved to another grant: %v", err)
	}
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }
