package keys_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/hugr-lab/tresor-server/internal/keys"
)

// a move to another KEK (spec 011): values sealed under A; then B current and A previous - values read, a new
// write under a B data key, rewrap moves every data key; then B alone reads everything; with a data key left
// under A, A removed: ErrSealed
func TestMoveToAnotherKEK(t *testing.T) {
	st := newStore()
	a, b := wrapper(t, 1), wrapper(t, 2)
	before := keys.NewEnvelope(a, st, keys.Options{})
	id, sealed, err := before.Seal(ctx, []byte("aad"), []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}

	chained := keys.Chain(b, a)
	moving := keys.NewEnvelope(chained, st, keys.Options{})
	if plain, err := moving.Open(ctx, id, []byte("aad"), sealed); err != nil || string(plain) != "hunter2" {
		t.Fatalf("a value under the previous KEK: %q %v", plain, err)
	}
	id2, sealed2, err := moving.Seal(ctx, []byte("aad"), []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	if id2 == id {
		t.Fatal("a new write under the old KEK's data key: want a new data key under the current KEK")
	}
	bID, _ := b.Current(ctx)
	if dk, _ := st.Get(ctx, id2); dk.KEKID != bID {
		t.Fatalf("the new data key is under %s, want %s", dk.KEKID, bID)
	}
	if err := moving.Check(ctx); err != nil {
		t.Fatal(err)
	}

	// before the rewrap, B alone does not open the old value: fail closed
	alone := keys.NewEnvelope(b, st, keys.Options{})
	if _, err := alone.Open(ctx, id, []byte("aad"), sealed); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("B alone before the rewrap: %v", err)
	}

	n, err := moving.Rewrap(ctx, false, nil)
	if err != nil || n != 1 {
		t.Fatalf("rewrap: %d %v", n, err)
	}
	if n, err := moving.Rewrap(ctx, false, nil); err != nil || n != 0 {
		t.Fatalf("a second rewrap: %d %v", n, err)
	}
	after := keys.NewEnvelope(b, st, keys.Options{})
	for _, v := range []struct {
		id, plain string
		sealed    []byte
	}{{id, "hunter2", sealed}, {id2, "new", sealed2}} {
		if plain, err := after.Open(ctx, v.id, []byte("aad"), v.sealed); err != nil || string(plain) != v.plain {
			t.Fatalf("after the move: %q %v", plain, err)
		}
	}
}

func TestChainOwners(t *testing.T) {
	a, b, c := wrapper(t, 1), wrapper(t, 2), wrapper(t, 3)
	chained := keys.Chain(b, a)
	cID, _ := c.Current(ctx)
	if chained.Owns(cID) {
		t.Fatal("a KEK not in the chain is owned")
	}
	if _, err := chained.Unwrap(ctx, []byte("x"), cID); !errors.Is(err, keys.ErrSealed) || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("an unowned id: %v", err)
	}
	if _, err := chained.Root(ctx, cID); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("an unowned root: %v", err)
	}
	// wraps with the current one only
	if _, id, err := chained.Wrap(ctx, make([]byte, 32)); err != nil || !b.Owns(id) {
		t.Fatalf("wrap: %s %v", id, err)
	}
	// two owners of one id: refused, never the first that answers
	twice := keys.Chain(b, a, wrapper(t, 1))
	aID, _ := a.Current(ctx)
	if _, err := twice.Unwrap(ctx, []byte("x"), aID); err == nil || !strings.Contains(err.Error(), "two configured KEKs") {
		t.Fatalf("two owners: %v", err)
	}
	if err := keys.Distinct(ctx, b, a, wrapper(t, 1)); err == nil || !strings.Contains(err.Error(), "keys.previous[0] and keys.previous[1]") {
		t.Fatalf("distinct: %v", err)
	}
	if err := keys.Distinct(ctx, b, wrapper(t, 2)); err == nil || !strings.Contains(err.Error(), "keys and keys.previous[0]") {
		t.Fatalf("the current one as previous: %v", err)
	}
	if err := keys.Distinct(ctx, b, a); err != nil {
		t.Fatal(err)
	}
	if keys.Chain(b) != b {
		t.Fatal("a chain of one is the KEK itself")
	}
}
