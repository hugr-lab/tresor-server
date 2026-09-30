package state

import (
	"context"
	"errors"
	"time"
)

// Delegation is a grant for a server to act for a user (tresor specs/007, 009), as stored (spec 002). Its id is
// a bearer credential and is never stored: rows are keyed by its SHA-256.
type Delegation struct {
	IDHash      []byte
	ActorOwner  string // the subject: of the server it was issued to - only it may present the grant
	ActorClient string // its client: principal
	ActorIssuer string
	UserOwner   string // the user's subject: principal, for revocation by subject
	User        []byte // the verified caller the grant speaks for (JSON), as taken at the exchange
	ExpiresAt   time.Time
	// Subject is the user's token at the exchange (a bearer token for this service): kept only when the
	// actor may use minted secrets, sealed at rest, never read after SubjectExpiresAt. Get leaves it out;
	// SubjectToken reads it.
	Subject          []byte
	SubjectExpiresAt time.Time
}

// MintedToken is one of a grant's minted tokens (tresor specs/010): the user's, for one audience and scope.
// A replica renews it by compare-and-set on Version: refresh tokens rotate, and one must not be spent twice.
type MintedToken struct {
	Key     string // the audience and the scope
	Version int64
	Token   []byte // the token (JSON), sealed at rest; nil when minting failed for good
	Failed  string // why minting failed for good (the IdP's refusal), never a token
}

var (
	// ErrTooMany: the actor holds as many live grants as it may.
	ErrTooMany = errors.New("too many delegation grants")
)

// DelegationStore keeps the delegation grants and their minted tokens, for every replica to honour.
// An expired grant is not found; expired rows go when a grant is next put.
type DelegationStore interface {
	// Put stores a new grant, unless its actor holds maxPerActor live grants already (ErrTooMany): the
	// count and the insert are one step.
	Put(ctx context.Context, d Delegation, maxPerActor int) error
	// Count is how many live grants an actor holds: the check before a grant's minting.
	Count(ctx context.Context, actorOwner string, now time.Time) (int, error)
	// Get returns a live grant without its subject token, or ErrNotFound.
	Get(ctx context.Context, idHash []byte, now time.Time) (*Delegation, error)
	// SubjectToken returns a live grant's subject token while it lives, or ErrNotFound.
	SubjectToken(ctx context.Context, idHash []byte, now time.Time) ([]byte, error)
	// Delete removes a grant and its tokens; false when there was none.
	Delete(ctx context.Context, idHash []byte) (bool, error)
	// DeleteWhere removes the grants of an actor client, of a user, or both ("" matches any; not both
	// empty): how many.
	DeleteWhere(ctx context.Context, actorClient, userOwner string) (int, error)
	// Token returns a grant's minted token for a key, or ErrNotFound.
	Token(ctx context.Context, idHash []byte, key string) (*MintedToken, error)
	// PutToken stores t, compare-and-set: from version 0 (none yet) or from t.Version-1. Another replica
	// that wrote first: ErrConflict, and the caller reads its token.
	PutToken(ctx context.Context, idHash []byte, t MintedToken) error
}
