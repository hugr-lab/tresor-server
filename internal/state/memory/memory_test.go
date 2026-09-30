package memory

import (
	"testing"

	"github.com/hugr-lab/tresor-server/internal/state/statetest"
)

func TestStore(t *testing.T) {
	statetest.Run(t, func(*testing.T) statetest.Handles { return statetest.Handles{First: New()} })
}
