package sqlstore

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/state"
)

// spec 014: who may use what cannot change behind the store - a grant added, a scope or a delegation's actor
// changed, a token's failure changed, a row from another installation: refused (a list leaves the secret out);
// a rollback of a whole row is not detected (documented)
func TestMACRefusesChanges(t *testing.T) {
	s := openAt(t, filepath.Join(t.TempDir(), "tresor.db"), kek(t, 1))
	put(t, s, "lake", "material")
	put(t, s, "other", "x")
	refused := func(what string) {
		t.Helper()
		if _, err := s.Get(ctx, "lake"); !errors.Is(err, keys.ErrSealed) {
			t.Fatalf("%s: Get: %v", what, err)
		}
		if _, err := s.Describe(ctx, "lake"); !errors.Is(err, keys.ErrSealed) {
			t.Fatalf("%s: Describe: %v", what, err)
		}
		if list, err := s.List(ctx); err != nil || len(list) != 1 || list[0].Name != "other" {
			t.Fatalf("%s: the list leaves it out: %v %v", what, list, err)
		}
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// a grant row added behind the store
	exec(`INSERT INTO grants (secret, id, position, principal, verbs) VALUES ('lake', 'g-me', 0, 'role:me', '["use"]')`)
	refused("a grant added")
	exec(`DELETE FROM grants WHERE id = 'g-me'`)
	if _, err := s.Get(ctx, "lake"); err != nil {
		t.Fatalf("the grant removed again: %v", err)
	}
	// the scope changed
	exec(`UPDATE secrets SET scope = '["s3://elsewhere"]' WHERE name = 'lake'`)
	refused("the scope changed")
	// only a delete passes for a row that does not verify
	if _, err := s.Update(ctx, "lake", func(cur *state.Secret) (*state.Secret, error) {
		cur.Version++
		return cur, nil
	}); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("rewritten blind: %v", err)
	}
	if _, err := s.Update(ctx, "lake", func(*state.Secret) (*state.Secret, error) { return nil, nil }); err != nil {
		t.Fatalf("a delete: %v", err)
	}
}

func TestMACDelegations(t *testing.T) {
	s := openAt(t, filepath.Join(t.TempDir(), "tresor.db"), kek(t, 1))
	d := s.Delegations()
	now := time.Now()
	g := state.Delegation{IDHash: []byte("hash-1"), ActorOwner: "subject:iss|node", ActorClient: "client:node",
		UserOwner: "subject:iss|alice", User: []byte(`{}`), ExpiresAt: now.Add(time.Hour), Subject: []byte("subject-token"),
		SubjectExpiresAt: now.Add(time.Hour)}
	if err := d.Put(ctx, g, 10); err != nil {
		t.Fatal(err)
	}
	if err := d.PutToken(ctx, g.IDHash, state.MintedToken{Key: "api\x00", Version: 1, Failed: "refused"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Get(ctx, g.IDHash, now); err != nil {
		t.Fatal(err)
	}
	if tok, err := d.Token(ctx, g.IDHash, "api\x00"); err != nil || tok.Failed != "refused" {
		t.Fatalf("the token: %v %v", tok, err)
	}
	if _, err := s.db.Exec(`UPDATE delegation_tokens SET failed = ''`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Token(ctx, g.IDHash, "api\x00"); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("a token's failure hidden: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE delegations SET actor_client = 'client:evil'`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Get(ctx, g.IDHash, now); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("the actor changed: %v", err)
	}
	if _, err := d.SubjectToken(ctx, g.IDHash, now); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("the subject of a changed grant: %v", err)
	}
}

// a row copied from another database under the same KEK does not verify: the installation's id is in the MAC;
// a whole row put back (a rollback) does - spec 014 says so
func TestMACInstallationAndRollback(t *testing.T) {
	dir := t.TempDir()
	a := openAt(t, filepath.Join(dir, "a.db"), kek(t, 1))
	b := openAt(t, filepath.Join(dir, "b.db"), kek(t, 1))
	put(t, a, "lake", "from-a")
	put(t, b, "lake", "from-b")
	if _, err := b.db.Exec(`ATTACH DATABASE ? AS a`, filepath.Join(dir, "a.db")); err != nil {
		t.Fatal(err)
	}
	// a's whole key table too, so the data key opens: only the installation differs
	if _, err := b.db.Exec(`INSERT OR IGNORE INTO data_keys SELECT * FROM a.data_keys`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`UPDATE secrets SET (row_id, scope, redact_keys, version, created_at, updated_at, data_key_id, sealed, mac) =
		(SELECT row_id, scope, redact_keys, version, created_at, updated_at, data_key_id, sealed, mac FROM a.secrets WHERE name = 'lake')
		WHERE name = 'lake'`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(ctx, "lake"); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("a row of another installation: %v", err)
	}

	// a rollback: the row as it was, put back whole - accepted
	c := openAt(t, filepath.Join(dir, "c.db"), kek(t, 1))
	put(t, c, "lake", "v1")
	var old struct {
		version         int64
		sealed, mac     []byte
		key, updatedRaw string
	}
	if err := c.db.QueryRow(`SELECT version, sealed, mac, data_key_id, updated_at FROM secrets WHERE name = 'lake'`).
		Scan(&old.version, &old.sealed, &old.mac, &old.key, &old.updatedRaw); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Update(ctx, "lake", func(cur *state.Secret) (*state.Secret, error) {
		cur.Version++
		cur.Grants = append(cur.Grants, state.Grant{ID: "g", Principal: "role:a", Verbs: []string{"use"}})
		return cur, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.Exec(`UPDATE secrets SET version = ?, sealed = ?, mac = ?, data_key_id = ?, updated_at = ? WHERE name = 'lake'`,
		old.version, old.sealed, old.mac, old.key, old.updatedRaw); err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.Exec(`DELETE FROM grants`); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Get(ctx, "lake"); err != nil || got.Version != old.version {
		t.Fatalf("a whole row rolled back is not detected (spec 014): %v %v", got, err)
	}
}

// the upgrade: rows with no MAC read while checks are off; with checks on they are refused until FillMACs
func TestMACUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tresor.db")
	plain := openWith(t, path, kek(t, 1), Options{})
	put(t, plain, "lake", "material")
	if err := plain.Delegations().Put(ctx, state.Delegation{IDHash: []byte("h"), ActorOwner: "a", ActorClient: "c",
		UserOwner: "u", User: []byte(`{}`), ExpiresAt: time.Now().Add(time.Hour)}, 10); err != nil {
		t.Fatal(err)
	}
	// as written before spec 014: no MAC
	for _, q := range []string{`UPDATE secrets SET mac = NULL`, `UPDATE delegations SET mac = NULL, subject_key_id = ''`} {
		if _, err := plain.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := plain.Get(ctx, "lake"); err != nil {
		t.Fatalf("checks off: %v", err)
	}
	plain.Close()
	checked := openAt(t, path, kek(t, 1))
	if _, err := checked.Get(ctx, "lake"); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("checks on, no MAC: %v", err)
	}
	if n, err := checked.FillMACs(ctx); err != nil || n != 2 {
		t.Fatalf("filled: %d %v", n, err)
	}
	if _, err := checked.Get(ctx, "lake"); err != nil {
		t.Fatalf("after FillMACs: %v", err)
	}
	if _, err := checked.Delegations().Get(ctx, []byte("h"), time.Now()); err != nil {
		t.Fatalf("a grant after FillMACs: %v", err)
	}
	if n, _ := checked.FillMACs(ctx); n != 0 {
		t.Fatalf("filled again: %d", n)
	}
}
