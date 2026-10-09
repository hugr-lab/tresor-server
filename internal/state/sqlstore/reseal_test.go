package sqlstore

import (
	"path/filepath"
	"testing"
	"time"
)

// spec 018: a row changed behind the store, or with no MAC, is not moved - reseal never vouches for it - and
// its data key is kept
func TestResealSkipsWhatDoesNotVerify(t *testing.T) {
	s := openAt(t, filepath.Join(t.TempDir(), "tresor.db"), kek(t, 1))
	put(t, s, "lake", "material")
	put(t, s, "other", "x")
	put(t, s, "bare", "y")
	old, err := s.envelope.ActiveID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE secrets SET scope = '["s3://elsewhere"]' WHERE name = 'lake'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE secrets SET mac = NULL WHERE name = 'bare'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.envelope.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	moved, skipped, err := s.Reseal(ctx)
	if err != nil || moved != 1 || skipped != 2 {
		t.Fatalf("moved %d, skipped %d, %v", moved, skipped, err)
	}
	inUse, err := s.DataKeysInUse(ctx)
	if err != nil || !inUse[old] {
		t.Fatalf("the old key is still used: %v %v", inUse, err)
	}
	s.envelope.SetClock(func() time.Time { return time.Now().Add(time.Hour) })
	kept, err := s.envelope.Retire(ctx, inUse)
	if err != nil || len(kept) != 1 || kept[0].ID != old || kept[0].Reason == "" {
		t.Fatalf("kept: %+v %v", kept, err)
	}
	if got, err := s.Get(ctx, "other"); err != nil || got.Version != 1 {
		t.Fatalf("the moved row: %+v %v", got, err)
	}
}
