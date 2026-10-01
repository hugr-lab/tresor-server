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

// Update over a broken row: a delete passes (nothing that opens is lost), anything else is refused, as the SQL
// stores do
func (b broken) Update(ctx context.Context, name string, fn func(*state.Secret) (*state.Secret, error)) (*state.Secret, error) {
	return b.Store.Update(ctx, name, func(cur *state.Secret) (*state.Secret, error) {
		next, err := fn(cur)
		if err == nil && next != nil && cur != nil {
			return nil, fmt.Errorf("secret %s: its params: %w", name, keys.ErrSealed)
		}
		return next, err
	})
}

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

// a write over a value that does not open: 500 too; a delete still passes
func TestSealedWrites(t *testing.T) {
	f := newFixture(t, "")
	f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret)
	f.srv.store = broken{f.srv.store}
	for name, r := range map[string]reply{
		"a put":   f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret),
		"a grant": f.do("PUT", "/v1/secrets/lake/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`),
	} {
		if r.status != 500 || r.problemType(t) != "service_error" {
			t.Errorf("%s over a value that does not open: %d %s", name, r.status, r.body)
		}
	}
	if r := f.do("DELETE", "/v1/secrets/lake", f.admin, ""); r.status != 204 {
		t.Fatalf("a delete of it: %d %s", r.status, r.body)
	}
}

// sealedTokens is a store whose grants' minted tokens no longer open
type sealedTokens struct{ state.DelegationStore }

func (s sealedTokens) Token(context.Context, []byte, string) (*state.MintedToken, error) {
	return nil, fmt.Errorf("a minted token: %w", keys.ErrSealed)
}

type withSealedTokens struct{ state.Store }

func (s withSealedTokens) Delegations() state.DelegationStore {
	return sealedTokens{s.Store.Delegations()}
}

// a grant's token that does not open: 500 service_error, not a retry
func TestSealedMintedToken(t *testing.T) {
	f := newFixture(t, "")
	node := f.idp.Service(t, "duckdb-secrets", "node", "nodes")
	f.do("PUT", "/v1/secrets/echo", f.admin, mintedSecret)
	f.do("PUT", "/v1/secrets/echo/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	g, r := f.grantFor(node, f.alice)
	if g == "" {
		t.Fatalf("exchange: %d %s", r.status, r.body)
	}
	f.srv.store = withSealedTokens{f.srv.store}
	if _, _, r := f.mintedMaterial(node, "Delegation", g); r.status != 500 || r.problemType(t) != "service_error" {
		t.Fatalf("a token that does not open: %d %s", r.status, r.body)
	}
}
