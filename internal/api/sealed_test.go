package api

import (
	"context"
	"fmt"
	"testing"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/state"
)

// broken is a store whose secrets' params no longer open: their data key's KEK is gone
type broken struct{ state.Store }

func (b broken) Get(ctx context.Context, name string) (*state.Secret, error) {
	if _, err := b.Store.Get(ctx, name); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("secret %s: its params: %w", name, keys.ErrSealed)
}

// a value that does not open is no outage: 500 service_error (tresor spec 016) - trying again will not help
// until an operator acts; the descriptor, which opens nothing, still answers
func TestSealedIsServiceError(t *testing.T) {
	f := newFixture(t, "")
	f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret)
	f.do("PUT", "/v1/secrets/lake/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	f.srv.store = broken{f.srv.store}
	r := f.do("GET", "/v1/secrets/lake", f.alice, "")
	if r.status != 500 || r.problemType(t) != "service_error" {
		t.Fatalf("a value that does not open: %d %s", r.status, r.body)
	}
	if r := f.do("GET", "/v1/secrets", f.alice, ""); r.status != 200 {
		t.Fatalf("the list: %d", r.status)
	}
}
