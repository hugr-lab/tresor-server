package kubestore

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/hugr-lab/tresor-server/internal/keys"
)

// dataKeys is the store's keys.DataKeyStore: a TresorDataKey per data key, authenticated by its tag under the
// KEK's root; the TresorKeyring names the active one, compare-and-set on its slot.
type dataKeys struct{ s *Store }

func toDataKey(o *object[dataKeySpec]) keys.DataKey {
	return keys.DataKey{ID: o.Spec.ID, KEKID: o.Spec.KEKID, Wrapped: o.Spec.Wrapped, Tag: o.Spec.Tag,
		CreatedAt: fromNanos(o.Spec.CreatedAt)}
}

// read reads one data key's resource; nil when there is none, or its name and id do not match (the tag
// covers the id: a resource renamed is no data key).
func (k dataKeys) read(ctx context.Context, id string) (*object[dataKeySpec], error) {
	name, ok := dataKeyName(id)
	if !ok {
		return nil, nil
	}
	o, err := k.s.dataKeys.get(ctx, name)
	if err != nil || o == nil {
		return nil, err
	}
	if o.Spec.ID != id || !untouched(o.Metadata, "") {
		return nil, nil
	}
	return o, nil
}

func (k dataKeys) Get(ctx context.Context, id string) (keys.DataKey, error) {
	o, err := k.read(ctx, id)
	if err != nil {
		return keys.DataKey{}, err
	}
	if o == nil {
		return keys.DataKey{}, keys.ErrNoDataKey
	}
	return toDataKey(o), nil
}

func (k dataKeys) Active(ctx context.Context) (keys.DataKey, int64, error) {
	ring, err := k.s.keyrings.get(ctx, keyringName)
	if err != nil {
		return keys.DataKey{}, 0, err
	}
	if ring == nil {
		return keys.DataKey{}, 0, keys.ErrNoDataKey
	}
	dk, err := k.Get(ctx, ring.Spec.DataKeyID)
	return dk, ring.Spec.Slot, err
}

// Activate stores dk and makes it active, compare-and-set on the slot: the first activation creates the
// keyring (AlreadyExists: another replica's came first), a later one updates it at its resourceVersion. A data
// key left by a lost race is harmless.
func (k dataKeys) Activate(ctx context.Context, dk keys.DataKey, slot int64) error {
	name, ok := dataKeyName(dk.ID)
	if !ok {
		return fmt.Errorf("data key id %q makes no resource name", dk.ID)
	}
	if _, err := k.s.dataKeys.create(ctx, &object[dataKeySpec]{Metadata: meta(name), Spec: dataKeySpec{
		ID: dk.ID, KEKID: dk.KEKID, Wrapped: dk.Wrapped, Tag: dk.Tag, CreatedAt: nanos(dk.CreatedAt)}}); err != nil {
		return err
	}
	// a race lost: the key is removed again (best effort: one left is an orphan, retired by reseal -retire)
	lost := func() error {
		_, _ = k.s.dataKeys.remove(ctx, name, nil)
		return keys.ErrKeyRace
	}
	if slot == 0 {
		_, err := k.s.keyrings.create(ctx, &object[keyringSpec]{Metadata: meta(keyringName),
			Spec: keyringSpec{DataKeyID: dk.ID, Slot: 1}})
		if apierrors.IsAlreadyExists(err) {
			return lost()
		}
		return err
	}
	ring, err := k.s.keyrings.get(ctx, keyringName)
	if err != nil {
		return err
	}
	if ring == nil || ring.Spec.Slot != slot {
		return lost()
	}
	ring.Spec = keyringSpec{DataKeyID: dk.ID, Slot: slot + 1}
	_, err = k.s.keyrings.update(ctx, ring)
	if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
		return lost()
	}
	return err
}

func (k dataKeys) List(ctx context.Context) ([]keys.DataKey, error) {
	all, err := k.s.dataKeys.list(ctx, "")
	if err != nil {
		return nil, err
	}
	out := make([]keys.DataKey, 0, len(all))
	for _, o := range all {
		if name, ok := dataKeyName(o.Spec.ID); ok && name == o.Metadata.Name {
			out = append(out, toDataKey(o))
		}
	}
	return out, nil
}

// Rewrapped replaces a data key's wrap and tag, compare-and-set on the KEK id it was read with: the
// resourceVersion carries it.
func (k dataKeys) Rewrapped(ctx context.Context, id, fromKEKID string, wrapped []byte, kekID string, tag []byte) (bool, error) {
	for range maxAttempts {
		o, err := k.read(ctx, id)
		if err != nil || o == nil || o.Spec.KEKID != fromKEKID {
			return false, err
		}
		o.Spec.KEKID, o.Spec.Wrapped, o.Spec.Tag = kekID, wrapped, tag
		_, err = k.s.dataKeys.update(ctx, o)
		if apierrors.IsConflict(err) {
			continue // read it again: another rewrap, or something else
		}
		return err == nil, err
	}
	return false, fmt.Errorf("data key %s kept changing under its rewrap", id)
}

// Delete removes a data key's resource (spec 018) at the resourceVersion read, never the active one's.
func (k dataKeys) Delete(ctx context.Context, id string) (bool, error) {
	ring, err := k.s.keyrings.get(ctx, keyringName)
	if err != nil {
		return false, err
	}
	if ring != nil && ring.Spec.DataKeyID == id {
		return false, nil
	}
	o, err := k.read(ctx, id)
	if err != nil || o == nil {
		return false, err
	}
	removed, err := k.s.dataKeys.remove(ctx, o.Metadata.Name, o)
	if apierrors.IsConflict(err) {
		return false, nil // changed since: kept
	}
	return removed, err
}
