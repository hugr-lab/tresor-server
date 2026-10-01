package api

// Delegation (specs/007, specs/009, protocol *Delegation*): a server allowed to act for users (the actor
// policy) exchanges a user's token for a grant and then calls with its own token plus the grant. A grant
// proves "this request is for user X's session". `use` is the ACTOR's own - the user gets nothing beyond what
// an admin granted the server; management passes through only for a user who is an admin, and only the
// verbs the actor policy lists (administration through a duckdb-acl node).

// Grants are kept in the state store (spec 002), for every replica to honour: keyed by the SHA-256 of their
// id - a bearer credential, never stored - with the user's subject token and minted tokens sealed.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/hugr-lab/tresor-server/internal/auth"
	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/state"
)

const (
	defaultGrantTTL   = time.Hour
	maxGrantTTL       = 8 * time.Hour
	maxGrantsPerActor = 10000 // live grants per actor: one allowed actor must not exhaust the others' room
)

// grant is a delegation grant, as read from the store for one request.
type grant struct {
	idHash      []byte
	actorOwner  string // the subject: of the server it was issued to - only it may present the grant
	actorClient string // its client: principal
	actorIssuer string
	user        auth.Caller
	expires     time.Time
	// keepsSubject: the user's token was kept (sealed) at the exchange, for what is minted later
	keepsSubject bool
}

type grantKey struct{}

// grantOf is the delegation grant the request was made under, or nil.
func grantOf(r *http.Request) *grant {
	gr, _ := r.Context().Value(grantKey{}).(*grant)
	return gr
}

// errGrantStore: the store did not answer - 503, not a refusal; or, with keys.ErrSealed, a grant it holds does
// not verify (changed behind it) - 500 (grantStoreProblem).
var errGrantStore = errors.New("the delegation grants could not be read")

// grantStoreProblem answers errGrantStore.
func grantStoreProblem(w http.ResponseWriter, err error, detail string) {
	if errors.Is(err, keys.ErrSealed) {
		problem(w, http.StatusInternalServerError, "service_error", "a delegation grant the service holds does not verify")
		return
	}
	problem(w, http.StatusServiceUnavailable, "service_unavailable", detail)
}

func hashGrantID(id string) []byte {
	sum := sha256.Sum256([]byte(id))
	return sum[:]
}

// loadGrant reads a live grant by its id: nil when there is none (or it expired).
func (s *Server) loadGrant(ctx context.Context, id string) (*grant, error) {
	if id == "" {
		return nil, nil
	}
	d, err := s.store.Delegations().Get(ctx, hashGrantID(id), s.now())
	if errors.Is(err, state.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		s.log.Error("delegation grants: the store failed", "error", err.Error())
		if errors.Is(err, keys.ErrSealed) {
			return nil, fmt.Errorf("%w: %w", errGrantStore, keys.ErrSealed)
		}
		return nil, errGrantStore
	}
	gr := &grant{idHash: d.IDHash, actorOwner: d.ActorOwner, actorClient: d.ActorClient, actorIssuer: d.ActorIssuer,
		expires: d.ExpiresAt, keepsSubject: d.HasSubject}
	if err := json.Unmarshal(d.User, &gr.user); err != nil {
		return nil, fmt.Errorf("%w: a grant's user does not read: %w", errGrantStore, keys.ErrSealed)
	}
	return gr, nil
}

// actorVerbs is what the policy lets this server (its client: principal, from this issuer) do for users;
// nil when it may not act at all.
func (s *Server) actorVerbs(client, issuer string) []string {
	for _, a := range s.cfg.Policy.Actors {
		if client != "" && a.Principal == client &&
			(a.Issuer == "" || config.IssuerKey(a.Issuer) == config.IssuerKey(issuer)) {
			return a.Verbs
		}
	}
	return nil
}

func (s *Server) actorAllowed(client, issuer string) bool {
	return len(s.actorVerbs(client, issuer)) > 0
}

// delegated resolves the Delegation header: the effective caller - the user's identity, with Actor set and
// the actor's own principals for every permission check - or an error that is always unauthenticated to the
// client: a grant presented by anyone but its actor is no grant.
func (s *Server) delegated(r *http.Request, actor *auth.Caller) (*auth.Caller, *grant, error) {
	id := strings.TrimSpace(r.Header.Get("Delegation"))
	gr, err := s.loadGrant(r.Context(), id)
	if err != nil {
		return nil, nil, err
	}
	if gr == nil {
		return nil, nil, errors.New("no such delegation grant (or expired)")
	}
	if gr.actorOwner != actor.Owner() {
		return nil, nil, errors.New("a delegation grant presented by another actor")
	}
	user := gr.user
	user.Principals = slices.Clone(gr.user.Principals)
	user.Actor = gr.actorClient
	user.ActorIssuer = gr.actorIssuer
	user.ActorPrincipals = slices.Clone(actor.Principals)
	user.ExpiresAt = gr.expires
	return &user, gr, nil
}

// --- grants ------------------------------------------------------------------------------------------

func (s *Server) exchange(w http.ResponseWriter, r *http.Request) {
	actor := callerOf(r)
	if actor.Actor != "" {
		problem(w, http.StatusForbidden, "actor_not_allowed", "a grant is exchanged with the server's own token only")
		return
	}
	client := actor.Client()
	if !actor.Service || !s.actorAllowed(client, actor.Issuer) {
		problem(w, http.StatusForbidden, "actor_not_allowed", "this caller may not act for users")
		return
	}
	var body struct {
		SubjectToken string `json:"subject_token"`
		TTL          int64  `json:"ttl"`
	}
	if err := readJSON(r, &body); err != nil || body.SubjectToken == "" {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "an exchange is {subject_token, ttl?}")
		return
	}
	user, err := s.verifier.Verify(r.Context(), body.SubjectToken)
	if err != nil {
		s.log.Warn("subject token refused", "actor", client, "reason", err.Error())
		problem(w, http.StatusUnauthorized, "unauthenticated", "the subject token is missing, invalid or expired")
		return
	}
	// a grant is a person's, for a server: not a service's, and never the actor's own
	if user.Service || user.Owner() == actor.Owner() {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "the subject token must be a person's")
		return
	}
	ttl := defaultGrantTTL
	if body.TTL > 0 && body.TTL < int64(maxGrantTTL/time.Second) { // bounded before the multiplication
		ttl = time.Duration(body.TTL) * time.Second
	} else if body.TTL > 0 {
		ttl = maxGrantTTL
	}
	expires := s.now().Add(ttl)
	grants := s.store.Delegations()
	// before any exchange at the IdP
	n, err := grants.Count(r.Context(), actor.Owner(), s.now())
	if err != nil {
		s.log.Error("delegation grants: the store failed", "error", err.Error())
		problem(w, http.StatusServiceUnavailable, "service_unavailable", "the delegation grants could not be read")
		return
	}
	if n >= maxGrantsPerActor {
		problem(w, http.StatusServiceUnavailable, "service_unavailable", "too many delegation grants")
		return
	}
	// the user's tokens for what the server may mint (specs/010): now, while the subject token lives
	mayMint := slices.Contains(s.actorVerbs(client, actor.Issuer), "use")
	var minted map[string]mintResult
	if mayMint {
		minted = s.mintAtGrant(r.Context(), user, body.SubjectToken, actor)
	}
	if r.Context().Err() != nil {
		return // the server gave up waiting: no grant nobody holds, with its refresh tokens
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic(err) // no randomness, no grants
	}
	id := hex.EncodeToString(raw)
	userJSON, err := json.Marshal(user)
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "service_unavailable", "the grant could not be stored")
		return
	}
	d := state.Delegation{IDHash: hashGrantID(id), ActorOwner: actor.Owner(), ActorClient: client,
		ActorIssuer: actor.Issuer, UserOwner: user.Owner(), User: userJSON, ExpiresAt: expires}
	if mayMint { // kept, sealed, for what could not be minted now - only while it lives
		d.Subject, d.SubjectExpiresAt = []byte(body.SubjectToken), user.ExpiresAt
	}
	if err := grants.Put(r.Context(), d, maxGrantsPerActor); errors.Is(err, state.ErrTooMany) {
		problem(w, http.StatusServiceUnavailable, "service_unavailable", "too many delegation grants")
		return
	} else if err != nil {
		s.log.Error("delegation grants: the store failed", "error", err.Error())
		problem(w, http.StatusServiceUnavailable, "service_unavailable", "the delegation grant could not be stored")
		return
	}
	for key, res := range minted {
		if err := s.storeMinted(r.Context(), d.IDHash, key, 1, res); err != nil {
			// minted lazily from the subject token instead, while it lives
			s.log.Warn("a grant's minted token was not stored", "actor", client, "error", err.Error())
		}
	}
	s.log.Info("delegation granted", "actor", client, "user", user.Owner(), "expires", expires.UTC())
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "subject": user.Subject, "actor": client, "expires_at": expires.UTC().Format(time.RFC3339),
	})
}

// revokeGrants is central revocation (DELETE /v1/delegations?actor=client:x&subject=subject:...): an
// admin revokes every grant matching the filters (at least one); anyone else revokes the grants made
// for themselves - a user ends every session a server holds for them.
func (s *Server) revokeGrants(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if c.Actor != "" {
		problem(w, http.StatusForbidden, "actor_not_allowed", "grants are revoked with the caller's own token")
		return
	}
	actor, subject := r.URL.Query().Get("actor"), r.URL.Query().Get("subject")
	if s.isAdmin(c) {
		if actor == "" && subject == "" {
			problem(w, http.StatusUnprocessableEntity, "invalid_secret", "name an actor or a subject to revoke")
			return
		}
	} else {
		subject = c.Owner() // anyone else: the grants made for themselves
	}
	n, err := s.store.Delegations().DeleteWhere(r.Context(), actor, subject)
	if err != nil {
		s.log.Error("delegation grants: the store failed", "error", err.Error())
		problem(w, http.StatusServiceUnavailable, "service_unavailable", "the grants could not be revoked")
		return
	}
	s.log.Info("delegation grants revoked", "by", c.Owner(), "actor", actor, "subject", subject, "count", n)
	writeJSON(w, http.StatusOK, map[string]any{"revoked": n})
}

func (s *Server) revokeGrant(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	gr, err := s.loadGrant(r.Context(), r.PathValue("id"))
	if err != nil {
		grantStoreProblem(w, err, "the grant could not be read")
		return
	}
	if gr == nil || c.Actor != "" || (gr.actorOwner != c.Owner() && !s.isAdmin(c)) {
		problem(w, http.StatusNotFound, "not_found", "no such delegation grant")
		return
	}
	if _, err := s.store.Delegations().Delete(r.Context(), gr.idHash); err != nil {
		s.log.Error("delegation grants: the store failed", "error", err.Error())
		problem(w, http.StatusServiceUnavailable, "service_unavailable", "the grant could not be revoked")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// refuse answers a missing verb: under a grant it is the actor policy's (a server uses only what it was
// granted, and passes on management only for admins, as its policy lists), otherwise no_verb.
func (s *Server) refuse(w http.ResponseWriter, c *auth.Caller, verb string) {
	if c.Actor != "" {
		problem(w, http.StatusForbidden, "actor_not_allowed", "this server may not "+verb+" for users")
		return
	}
	problem(w, http.StatusForbidden, "no_verb", "the caller's roles do not hold "+verb)
}
