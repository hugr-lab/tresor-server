package kubestore

import (
	"context"
	"errors"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/hugr-lab/tresor-server/internal/keys"
)

// Reseal moves every resource sealed or authenticated under another data key to the active one (spec 018): the
// secrets and variables, the delegation grants and their minted tokens - their material opened and sealed again
// with the same AAD - and the actors' counters and the installation's mark, MACed anew. The version and the
// times are kept; each move is an update at the resourceVersion read, and only of a resource that verifies
// (what does not is logged and counted as skipped).
func (s *Store) Reseal(ctx context.Context) (moved, skipped int, err error) {
	active, err := s.envelope.ActiveID(ctx)
	if err != nil {
		return 0, 0, err
	}
	// settle sorts a check's or a move's error: tampered or sealed is a skip, an outage stops the run
	settle := func(what string, err error) (bool, error) {
		if err == nil {
			return true, nil
		}
		if errors.Is(err, ErrTampered) || errors.Is(err, keys.ErrSealed) {
			skipped++
			s.log.Warn("tresor-server reseal: a resource left under its data key", "resource", what, "error", err.Error())
			return false, nil
		}
		return false, err
	}
	// updated counts an update; a conflict is a resource written meanwhile, under the active key already
	updated := func(err error) error {
		if err == nil {
			moved++
			return nil
		}
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	// resealed is plain sealed under aad again
	resealed := func(what, keyID string, aad, sealed []byte) (string, []byte, bool, error) {
		plain, err := s.envelope.Open(ctx, keyID, aad, sealed)
		if ok, err := settle(what, err); !ok {
			return "", nil, false, err
		}
		id, out, err := s.envelope.Seal(ctx, aad, plain)
		clear(plain)
		return id, out, err == nil, err
	}

	for _, st := range []*Store{s, s.vars} {
		all, err := st.secrets.list(ctx, "")
		if err != nil {
			return moved, skipped, err
		}
		for _, o := range all {
			sp := &o.Spec
			if sp.DataKeyID == active {
				continue
			}
			_, err := st.verified(ctx, o) // its name, its metadata, its MAC
			if ok, err := settle(o.Metadata.Name, err); !ok {
				if err != nil {
					return moved, skipped, err
				}
				continue
			}
			id, sealed, ok, err := resealed(o.Metadata.Name, sp.DataKeyID, st.paramsAAD(sp.RowID, sp.Name, sp.Version), sp.Sealed)
			if !ok {
				if err != nil {
					return moved, skipped, err
				}
				continue
			}
			sp.DataKeyID, sp.Sealed = id, sealed
			if sp.MAC, err = st.envelope.MAC(ctx, id, sp.canonical(st.space.kind, st.instance)); err != nil {
				return moved, skipped, err
			}
			_, err = st.secrets.update(ctx, o)
			if err := updated(err); err != nil {
				return moved, skipped, err
			}
		}
	}

	d := delegations{s}
	grants, err := s.grants.list(ctx, "")
	if err != nil {
		return moved, skipped, err
	}
	for _, o := range grants {
		g := &o.Spec
		if g.DataKeyID == active {
			continue
		}
		if ok, err := settle(o.Metadata.Name, d.checkGrant(ctx, o)); !ok {
			if err != nil {
				return moved, skipped, err
			}
			continue
		}
		id := active
		if g.SubjectSealed != nil {
			var sealed []byte
			var ok bool
			if id, sealed, ok, err = resealed(o.Metadata.Name, g.DataKeyID, subjectAAD(g.IDHash), g.SubjectSealed); !ok {
				if err != nil {
					return moved, skipped, err
				}
				continue
			}
			g.SubjectSealed = sealed
		}
		g.DataKeyID = id
		if g.MAC, err = s.envelope.MAC(ctx, id, g.canonical(s.instance)); err != nil {
			return moved, skipped, err
		}
		_, err = s.grants.update(ctx, o)
		if err := updated(err); err != nil {
			return moved, skipped, err
		}
	}

	tokens, err := s.tokens.list(ctx, "")
	if err != nil {
		return moved, skipped, err
	}
	for _, o := range tokens {
		t := &o.Spec
		if t.DataKeyID == active {
			continue
		}
		if ok, err := settle(o.Metadata.Name, d.checkToken(ctx, o, t.IDHash, string(t.Key))); !ok {
			if err != nil {
				return moved, skipped, err
			}
			continue
		}
		id := active
		if t.Sealed != nil {
			var sealed []byte
			var ok bool
			if id, sealed, ok, err = resealed(o.Metadata.Name, t.DataKeyID, tokenAAD(t.IDHash, string(t.Key), t.Version), t.Sealed); !ok {
				if err != nil {
					return moved, skipped, err
				}
				continue
			}
			t.Sealed = sealed
		}
		t.DataKeyID = id
		if t.MAC, err = s.envelope.MAC(ctx, id, t.canonical(s.instance)); err != nil {
			return moved, skipped, err
		}
		_, err = s.tokens.update(ctx, o)
		if err := updated(err); err != nil {
			return moved, skipped, err
		}
	}

	actors, err := s.actors.list(ctx, "")
	if err != nil {
		return moved, skipped, err
	}
	for _, o := range actors {
		a := &o.Spec
		if a.DataKeyID == active {
			continue
		}
		if ok, err := settle(o.Metadata.Name, d.checkActor(ctx, o, a.ActorOwner)); !ok {
			if err != nil {
				return moved, skipped, err
			}
			continue
		}
		a.DataKeyID = active
		if a.MAC, err = s.envelope.MAC(ctx, active, a.canonical(s.instance)); err != nil {
			return moved, skipped, err
		}
		_, err = s.actors.update(ctx, o)
		if err := updated(err); err != nil {
			return moved, skipped, err
		}
	}

	mark, err := s.keyrings.get(ctx, installationName)
	if err != nil {
		return moved, skipped, err
	}
	if mark != nil && mark.Spec.DataKeyID != active {
		sp := &mark.Spec
		err := s.check(ctx, installationName, sp.Instance == s.instance && untouched(mark.Metadata, ""), sp.DataKeyID,
			sp.canonical(s.instance), sp.MAC)
		if ok, err := settle(installationName, err); !ok {
			return moved, skipped, err
		}
		sp.DataKeyID = active
		if sp.MAC, err = s.envelope.MAC(ctx, active, sp.canonical(s.instance)); err != nil {
			return moved, skipped, err
		}
		_, err = s.keyrings.update(ctx, mark)
		if err := updated(err); err != nil {
			return moved, skipped, err
		}
	}
	return moved, skipped, nil
}

// DataKeysInUse names every data key a resource is sealed or authenticated under (spec 018: what -retire keeps).
func (s *Store) DataKeysInUse(ctx context.Context) (map[string]bool, error) {
	used := map[string]bool{}
	add := func(id string) {
		if id != "" {
			used[id] = true
		}
	}
	for _, st := range []*Store{s, s.vars} {
		all, err := st.secrets.list(ctx, "")
		if err != nil {
			return nil, err
		}
		for _, o := range all {
			add(o.Spec.DataKeyID)
		}
	}
	grants, err := s.grants.list(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, o := range grants {
		add(o.Spec.DataKeyID)
	}
	tokens, err := s.tokens.list(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, o := range tokens {
		add(o.Spec.DataKeyID)
	}
	actors, err := s.actors.list(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, o := range actors {
		add(o.Spec.DataKeyID)
	}
	mark, err := s.keyrings.get(ctx, installationName)
	if err != nil {
		return nil, err
	}
	if mark != nil {
		add(mark.Spec.DataKeyID)
	}
	return used, nil
}
