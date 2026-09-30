package sqlstore

import (
	"bytes"
	"context"
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
	s.Close()
	other := openAt(t, path, kek(t, 2))
	if _, err := other.Get(ctx, "b"); err == nil {
		t.Fatal("params open under another KEK")
	}
}

// one replica serves a SQLite database: another waits, serving nothing, and takes over when the first stops
func TestLease(t *testing.T) {
	leaseTTL, leaseRenew = 600*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { leaseTTL, leaseRenew = 15*time.Second, 5*time.Second })
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
