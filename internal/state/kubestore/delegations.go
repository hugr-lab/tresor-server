package kubestore

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/state"
)

// delegations is the store's state.DelegationStore: a TresorGrant per delegation grant, a TresorMintedToken per
// minted token, a TresorActor per actor for the per-actor limit. Tokens go with their grant by the store's own
// deletes; an owner reference to the grant is a backstop for the garbage collector.
type delegations struct{ s *Store }

func (s *Store) Delegations() state.DelegationStore { return delegations{s} }

// The AADs are the SQL stores': a value sealed under one store's rules is sealed under the other's.
func subjectAAD(idHash []byte) []byte {
	return []byte("tresor-server/delegation/1\x00" + hex.EncodeToString(idHash))
}

func tokenAAD(idHash []byte, key string, version int64) []byte {
	return []byte("tresor-server/minted/1\x00" + hex.EncodeToString(idHash) + "\x00" + key + "\x00" + strconv.FormatInt(version, 10))
}

func grantLabels(g *grantSpec) map[string]string {
	return map[string]string{labelActor: labelValue([]byte(g.ActorOwner)), labelClient: labelValue([]byte(g.ActorClient)),
		labelUser: labelValue([]byte(g.UserOwner))}
}

// check verifies what a resource's MAC covers against its metadata and its MAC. A KEK that does not answer is
// no verdict (not ErrTampered).
func (s *Store) check(ctx context.Context, what string, ok bool, dataKeyID string, msg, mac []byte) error {
	if !ok {
		return fmt.Errorf("%w: %s", ErrTampered, what)
	}
	if err := s.envelope.Verify(ctx, dataKeyID, msg, mac); err != nil {
		if errors.Is(err, keys.ErrSealed) {
			return fmt.Errorf("%w: %s: %w", ErrTampered, what, err)
		}
		return err
	}
	return nil
}

func (d delegations) checkGrant(ctx context.Context, o *object[grantSpec]) error {
	g := &o.Spec
	ok := o.Metadata.Name == grantName(g.IDHash) && sameLabels(o.Metadata.Labels, grantLabels(g)) && untouched(o.Metadata, "")
	return d.s.check(ctx, o.Metadata.Name, ok, g.DataKeyID, g.canonical(d.s.instance), g.MAC)
}

// grant reads a live grant, checked; nil when there is none, it expired, or it is being deleted.
func (d delegations) grant(ctx context.Context, idHash []byte, now time.Time) (*object[grantSpec], error) {
	o, err := d.s.grants.get(ctx, grantName(idHash))
	if err != nil || o == nil || o.Metadata.DeletionTimestamp != nil {
		return nil, err
	}
	if !bytes.Equal(o.Spec.IDHash, idHash) {
		return nil, fmt.Errorf("%w: %s holds another grant", ErrTampered, o.Metadata.Name)
	}
	if err := d.checkGrant(ctx, o); err != nil {
		return nil, err
	}
	if o.Spec.ExpiresAt <= now.UnixNano() {
		return nil, nil
	}
	return o, nil
}

func (d delegations) checkActor(ctx context.Context, o *object[actorSpec], owner string) error {
	a := &o.Spec
	ok := a.ActorOwner == owner && o.Metadata.Name == actorName(owner) && sameLabels(o.Metadata.Labels, nil) &&
		untouched(o.Metadata, "")
	return d.s.check(ctx, o.Metadata.Name, ok, a.DataKeyID, a.canonical(d.s.instance), a.MAC)
}

// Put stores a grant under the actor's limit with no lock: it reads the actor's counter, counts the actor's
// live grants, creates the grant, then moves the counter on at the version it read. A put that raced another
// loses the counter's compare-and-set, deletes the grant it made, and runs again. The limit is never passed;
// under racing puts near it, one may be refused while another's grant, about to be deleted, still counts -
// the SQL stores' lock does not do that.
func (d delegations) Put(ctx context.Context, g state.Delegation, maxPerActor int) error {
	s := d.s
	spec := grantSpec{IDHash: g.IDHash, ActorOwner: g.ActorOwner, ActorClient: g.ActorClient, ActorIssuer: g.ActorIssuer,
		UserOwner: g.UserOwner, User: string(g.User), ExpiresAt: nanos(g.ExpiresAt), SubjectExpiresAt: nanos(g.SubjectExpiresAt)}
	if err := validUTF8(spec.ActorOwner, spec.ActorClient, spec.ActorIssuer, spec.UserOwner, spec.User); err != nil {
		return err
	}
	var err error
	if g.Subject != nil {
		spec.DataKeyID, spec.SubjectSealed, err = s.envelope.Seal(ctx, subjectAAD(g.IDHash), g.Subject)
	} else {
		spec.DataKeyID, err = s.envelope.ActiveID(ctx)
	}
	if err != nil {
		return err
	}
	if spec.MAC, err = s.envelope.MAC(ctx, spec.DataKeyID, spec.canonical(s.instance)); err != nil {
		return err
	}
	name := grantName(g.IDHash)
	for range maxPutAttempts {
		actor, err := s.actors.get(ctx, actorName(g.ActorOwner))
		if err != nil {
			return err
		}
		counter := int64(0)
		if actor != nil {
			// checked before it is moved: a tampered counter is never re-MACed
			if err := d.checkActor(ctx, actor, g.ActorOwner); err != nil {
				return err
			}
			counter = actor.Spec.Counter
		}
		n, err := d.Count(ctx, g.ActorOwner, time.Now())
		if err != nil {
			return err
		}
		if n >= maxPerActor {
			return state.ErrTooMany
		}
		made, err := s.grants.create(ctx, &object[grantSpec]{Metadata: metaLabelled(name, grantLabels(&spec)), Spec: spec})
		if err != nil {
			return err
		}
		moved, err := d.moveCounter(ctx, actor, g.ActorOwner, counter+1)
		if err == nil && moved {
			return nil
		}
		// another put came first (or the counter did not move): the grant made is not this put's to keep
		if _, rerr := s.grants.remove(ctx, name, made); rerr != nil && err == nil {
			err = rerr
		}
		if err != nil {
			return err
		}
	}
	return state.ErrConflict
}

// moveCounter moves an actor's counter on, compare-and-set on the counter read (actor nil: none yet); false
// when another put moved it first.
func (d delegations) moveCounter(ctx context.Context, actor *object[actorSpec], owner string, counter int64) (bool, error) {
	s := d.s
	spec := actorSpec{ActorOwner: owner, Counter: counter}
	var err error
	if spec.DataKeyID, err = s.envelope.ActiveID(ctx); err != nil {
		return false, err
	}
	if spec.MAC, err = s.envelope.MAC(ctx, spec.DataKeyID, spec.canonical(s.instance)); err != nil {
		return false, err
	}
	if actor == nil {
		_, err = s.actors.create(ctx, &object[actorSpec]{Metadata: meta(actorName(owner)), Spec: spec})
		if apierrors.IsAlreadyExists(err) {
			return false, nil
		}
		return err == nil, err
	}
	actor.Spec = spec
	_, err = s.actors.update(ctx, actor)
	if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

func (d delegations) Count(ctx context.Context, actorOwner string, now time.Time) (int, error) {
	all, err := d.s.grants.list(ctx, selector(labelActor, []byte(actorOwner)))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, o := range all {
		if o.Metadata.DeletionTimestamp != nil || o.Spec.ActorOwner != actorOwner || o.Spec.ExpiresAt <= now.UnixNano() {
			continue
		}
		if err := d.checkGrant(ctx, o); errors.Is(err, keys.ErrSealed) {
			d.s.log.Error("a delegation grant's resource was changed behind the store: not counted", "resource",
				o.Metadata.Name, "error", err.Error())
			continue
		} else if err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

func (d delegations) Get(ctx context.Context, idHash []byte, now time.Time) (*state.Delegation, error) {
	o, err := d.grant(ctx, idHash, now)
	if err != nil {
		return nil, err
	}
	if o == nil {
		return nil, state.ErrNotFound
	}
	g := &o.Spec
	return &state.Delegation{IDHash: idHash, ActorOwner: g.ActorOwner, ActorClient: g.ActorClient, ActorIssuer: g.ActorIssuer,
		UserOwner: g.UserOwner, User: []byte(g.User), ExpiresAt: fromNanos(g.ExpiresAt),
		SubjectExpiresAt: fromNanos(g.SubjectExpiresAt), HasSubject: g.SubjectSealed != nil}, nil
}

func (d delegations) SubjectToken(ctx context.Context, idHash []byte, now time.Time) ([]byte, error) {
	o, err := d.grant(ctx, idHash, now)
	if err != nil {
		return nil, err
	}
	if o == nil || o.Spec.SubjectSealed == nil || o.Spec.SubjectExpiresAt <= now.UnixNano() {
		return nil, state.ErrNotFound
	}
	return d.s.envelope.Open(ctx, o.Spec.DataKeyID, subjectAAD(idHash), o.Spec.SubjectSealed)
}

// drop deletes a grant and its tokens; false when there was no grant.
func (d delegations) drop(ctx context.Context, name string, idHash []byte) (bool, error) {
	found, err := d.s.grants.remove(ctx, name, nil)
	if err != nil {
		return false, err
	}
	return found, d.s.tokens.removeAll(ctx, selector(labelGrant, idHash))
}

func (d delegations) Delete(ctx context.Context, idHash []byte) (bool, error) {
	return d.drop(ctx, grantName(idHash), idHash)
}

// DeleteWhere deletes the grants the labels select: one changed behind the store is deleted too - a delete
// gives no one anything.
func (d delegations) DeleteWhere(ctx context.Context, actorClient, userOwner string) (int, error) {
	if actorClient == "" && userOwner == "" {
		return 0, errors.New("revoking grants names an actor or a user")
	}
	sel := ""
	if actorClient != "" {
		sel = selector(labelClient, []byte(actorClient))
	}
	if userOwner != "" {
		if sel != "" {
			sel += ","
		}
		sel += selector(labelUser, []byte(userOwner))
	}
	all, err := d.s.grants.list(ctx, sel)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, o := range all {
		found, err := d.drop(ctx, o.Metadata.Name, o.Spec.IDHash)
		if err != nil {
			return n, err
		}
		if found {
			n++
		}
	}
	return n, nil
}

// Purge deletes the expired grants with their tokens, and the tokens whose grant is gone (a stripped label
// would leave them otherwise). The tokens are listed first: one minted after the grants are listed has a grant
// listed.
func (d delegations) Purge(ctx context.Context, now time.Time) (int, error) {
	// the actors' counters are read before the grants: a counter a put moves after this read has a newer
	// version (the delete is refused), and a put that moved it before created its grant before - the grant
	// list below sees it. Read after the grants, a counter created meanwhile would look idle, and a put from
	// no counter could then create it again past the limit.
	actors, err := d.s.actors.list(ctx, "")
	if err != nil {
		return 0, err
	}
	return d.purge(ctx, now, actors)
}

// purge is Purge with the actors' counters as read first.
func (d delegations) purge(ctx context.Context, now time.Time, actors []*object[actorSpec]) (int, error) {
	tokens, err := d.s.tokens.list(ctx, "")
	if err != nil {
		return 0, err
	}
	grants, err := d.s.grants.list(ctx, "")
	if err != nil {
		return 0, err
	}
	live := map[string]bool{}
	liveActors := map[string]bool{}
	n := 0
	for _, o := range grants {
		if o.Spec.ExpiresAt > now.UnixNano() && o.Metadata.DeletionTimestamp == nil {
			live[o.Metadata.Name] = true
			liveActors[actorName(o.Spec.ActorOwner)] = true
			continue
		}
		found, err := d.drop(ctx, o.Metadata.Name, o.Spec.IDHash)
		if err != nil {
			return n, err
		}
		if found {
			n++
		}
	}
	for _, t := range tokens {
		if !live[grantName(t.Spec.IDHash)] {
			if _, err := d.s.tokens.remove(ctx, t.Metadata.Name, nil); err != nil {
				return n, err
			}
		}
	}
	return n, d.dropIdleActors(ctx, actors, liveActors)
}

// dropIdleActors deletes the counters of actors with no live grant (spec 003's follow-up: one per actor ever
// seen otherwise), each compare-and-set on the version read before the grants were:
//   - a put that moved it after that read keeps it (Conflict; the next purge tries again);
//   - a put that read it before and moves it after finds it gone (NotFound), drops its grant and runs again;
//   - a put that found none creates one: a counter that did not exist when read is never deleted here.
func (d delegations) dropIdleActors(ctx context.Context, actors []*object[actorSpec], liveActors map[string]bool) error {
	for _, a := range actors {
		if liveActors[a.Metadata.Name] {
			continue
		}
		if _, err := d.s.actors.remove(ctx, a.Metadata.Name, a); err != nil && !apierrors.IsConflict(err) {
			return err
		}
	}
	return nil
}

func (d delegations) checkToken(ctx context.Context, o *object[tokenSpec], idHash []byte, key string) error {
	t := &o.Spec
	ok := bytes.Equal(t.IDHash, idHash) && string(t.Key) == key && o.Metadata.Name == tokenName(idHash, key) &&
		sameLabels(o.Metadata.Labels, map[string]string{labelGrant: labelValue(idHash)}) &&
		untouched(o.Metadata, grantName(idHash))
	return d.s.check(ctx, o.Metadata.Name, ok, t.DataKeyID, t.canonical(d.s.instance), t.MAC)
}

func (d delegations) Token(ctx context.Context, idHash []byte, key string) (*state.MintedToken, error) {
	g, err := d.grant(ctx, idHash, time.Now())
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, state.ErrNotFound // a token never outlives its grant
	}
	o, err := d.s.tokens.get(ctx, tokenName(idHash, key))
	if err != nil {
		return nil, err
	}
	if o == nil || o.Metadata.DeletionTimestamp != nil {
		return nil, state.ErrNotFound
	}
	if err := d.checkToken(ctx, o, idHash, key); err != nil {
		return nil, err
	}
	t := &state.MintedToken{Key: key, Version: o.Spec.Version, Failed: o.Spec.Failed}
	if o.Spec.Sealed != nil {
		if t.Token, err = d.s.envelope.Open(ctx, o.Spec.DataKeyID, tokenAAD(idHash, key, t.Version), o.Spec.Sealed); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func (d delegations) PutToken(ctx context.Context, idHash []byte, t state.MintedToken) error {
	s := d.s
	if t.Version < 1 {
		return state.ErrVersion
	}
	g, err := d.grant(ctx, idHash, time.Now())
	if err != nil {
		return err
	}
	if g == nil {
		return state.ErrNotFound // the grant is gone
	}
	spec := tokenSpec{IDHash: idHash, Key: []byte(t.Key), Version: t.Version, Failed: t.Failed}
	if err := validUTF8(t.Failed); err != nil {
		return err
	}
	if t.Token != nil {
		spec.DataKeyID, spec.Sealed, err = s.envelope.Seal(ctx, tokenAAD(idHash, t.Key, t.Version), t.Token)
	} else {
		spec.DataKeyID, err = s.envelope.ActiveID(ctx)
	}
	if err != nil {
		return err
	}
	if spec.MAC, err = s.envelope.MAC(ctx, spec.DataKeyID, spec.canonical(s.instance)); err != nil {
		return err
	}
	name := tokenName(idHash, t.Key)
	if t.Version == 1 {
		m := metaLabelled(name, map[string]string{labelGrant: labelValue(idHash)})
		m.OwnerReferences = ownedBy(g.Metadata.Name, g.Metadata.UID)
		_, err := s.tokens.create(ctx, &object[tokenSpec]{Metadata: m, Spec: spec})
		if apierrors.IsAlreadyExists(err) {
			return state.ErrConflict
		}
		return err
	}
	o, err := s.tokens.get(ctx, name)
	if err != nil {
		return err
	}
	if o == nil || o.Metadata.DeletionTimestamp != nil {
		return state.ErrConflict
	}
	// checked before it is written over
	if err := d.checkToken(ctx, o, idHash, t.Key); err != nil {
		return err
	}
	if o.Spec.Version != t.Version-1 {
		return state.ErrConflict
	}
	o.Spec = spec
	_, err = s.tokens.update(ctx, o)
	if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
		return state.ErrConflict
	}
	return err
}
