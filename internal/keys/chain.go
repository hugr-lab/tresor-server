package keys

import (
	"context"
	"fmt"
)

// Chain is the KEK and the ones before it (spec 011, keys.previous): it wraps with the current one only; a data
// key opens with the KEK that owns its KEK id, chosen by Owns, never by trying each - a wrong KEK's refusal and a
// tampered data key would look alike. An id no KEK owns is ErrSealed, as with one KEK.
func Chain(current KeyWrapper, previous ...KeyWrapper) KeyWrapper {
	if len(previous) == 0 {
		return current
	}
	return &chain{current: current, all: append([]KeyWrapper{current}, previous...)}
}

type chain struct {
	current KeyWrapper
	all     []KeyWrapper
}

func (c *chain) Wrap(ctx context.Context, dek []byte) ([]byte, string, error) {
	return c.current.Wrap(ctx, dek)
}
func (c *chain) Current(ctx context.Context) (string, error) { return c.current.Current(ctx) }

func (c *chain) Owns(kekID string) bool {
	for _, w := range c.all {
		if w.Owns(kekID) {
			return true
		}
	}
	return false
}

func (c *chain) owner(kekID string) (KeyWrapper, error) {
	var found KeyWrapper
	for _, w := range c.all {
		if w.Owns(kekID) {
			if found != nil {
				return nil, fmt.Errorf("two configured KEKs own the KEK id %s", kekID)
			}
			found = w
		}
	}
	if found == nil {
		return nil, fmt.Errorf("%w: a data key under a KEK that is not configured (%s)", ErrSealed, kekID)
	}
	return found, nil
}

func (c *chain) Unwrap(ctx context.Context, wrapped []byte, kekID string) ([]byte, error) {
	w, err := c.owner(kekID)
	if err != nil {
		return nil, err
	}
	return w.Unwrap(ctx, wrapped, kekID)
}

func (c *chain) Root(ctx context.Context, kekID string) ([]byte, error) {
	w, err := c.owner(kekID)
	if err != nil {
		return nil, err
	}
	return w.Root(ctx, kekID)
}

// Distinct refuses KEKs of which one owns another's current id: the same key configured twice, as keys and
// in keys.previous (a typo the chain would hide). A KEK that does not answer is not judged here: readiness
// reports it.
func Distinct(ctx context.Context, kek KeyWrapper, previous ...KeyWrapper) error {
	all := append([]KeyWrapper{kek}, previous...)
	for i, w := range all {
		id, err := w.Current(ctx)
		if err != nil {
			continue
		}
		for j, other := range all {
			if j != i && other.Owns(id) {
				return fmt.Errorf("%s and %s are the same KEK (%s)", position(i), position(j), id)
			}
		}
	}
	return nil
}

func position(i int) string {
	if i == 0 {
		return "keys"
	}
	return fmt.Sprintf("keys.previous[%d]", i-1)
}
