package traced

import (
	"context"
	"errors"
	"testing"

	"github.com/hugr-lab/tresor-server/internal/state"
	"github.com/hugr-lab/tresor-server/internal/state/memory"
	"github.com/hugr-lab/tresor-server/internal/state/statetest"
)

// a traced store is the store: the whole suite through it, fn's own errors passed on as they are
func TestStore(t *testing.T) {
	statetest.Run(t, func(t *testing.T) statetest.Handles { return statetest.Handles{First: Store(memory.New())} })
	st := Store(memory.New())
	mine := errors.New("refused by fn")
	if _, err := st.Update(context.Background(), "a", func(*state.Secret) (*state.Secret, error) { return nil, mine }); !errors.Is(err, mine) {
		t.Fatalf("fn's error: %v", err)
	}
	if _, err := st.Variables().Update(context.Background(), "a", func(*state.Secret) (*state.Secret, error) { return nil, mine }); !errors.Is(err, mine) {
		t.Fatalf("fn's error, a variable: %v", err)
	}
}
