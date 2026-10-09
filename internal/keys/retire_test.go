package keys_test

import (
	"testing"
	"time"

	"github.com/hugr-lab/tresor-server/internal/keys"
)

// spec 018: a key that lost an activation race sits between two active ones; the old active key is retired
// only once the active one has settled, never by the orphan's age - and an orphan made after the active key
// only once it is old
func TestRetireAroundOrphans(t *testing.T) {
	st := newStore()
	e := keys.NewEnvelope(wrapper(t, 1), st, keys.Options{})
	t0 := time.Now()
	at := func(d time.Duration) { e.SetClock(func() time.Time { return t0.Add(d) }) }
	at(0)
	old, err := e.ActiveID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	orphan := func(id string, d time.Duration) {
		st.mu.Lock()
		st.keys[id] = keys.DataKey{ID: id, KEKID: "local", CreatedAt: t0.Add(d).UTC()}
		st.mu.Unlock()
	}
	orphan("lost-race", time.Second) // a month before the next rotation
	at(31 * 24 * time.Hour)
	active, err := e.Rotate(ctx)
	if err != nil || active == old {
		t.Fatalf("rotate: %v", err)
	}
	orphan("being-activated", 31*24*time.Hour+time.Second)
	reasons := func(rs []keys.Retirement) map[string]string {
		out := map[string]string{}
		for _, r := range rs {
			out[r.ID] = r.Reason
		}
		return out
	}

	at(31*24*time.Hour + 2*time.Minute)
	got, err := e.Retire(ctx, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if r := reasons(got); r[old] == "" || r["lost-race"] == "" || r["being-activated"] == "" {
		t.Fatalf("all kept while the active key is new: %+v", got)
	}

	at(31*24*time.Hour + 10*time.Minute)
	got, err = e.Retire(ctx, map[string]bool{"lost-race": true})
	if err != nil {
		t.Fatal(err)
	}
	if r := reasons(got); r[old] != "" || r["being-activated"] != "" || r["lost-race"] == "" {
		t.Fatalf("settled: the old and the orphan retired, the one in use kept: %+v", got)
	}
	if _, err := st.Get(ctx, old); err == nil {
		t.Fatal("the old key is still stored")
	}
	if _, err := st.Get(ctx, active); err != nil {
		t.Fatalf("the active key: %v", err)
	}
}
