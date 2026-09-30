package memory

import (
	"testing"

	"github.com/hugr-lab/tresor-server/internal/state"
	"github.com/hugr-lab/tresor-server/internal/state/statetest"
)

func TestStore(t *testing.T) {
	statetest.Run(t, func(*testing.T) (state.Store, func() state.Store) { return New(), nil })
}
