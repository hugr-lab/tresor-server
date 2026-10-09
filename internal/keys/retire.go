package keys

import (
	"context"
	"errors"
	"slices"
	"time"
)

// Rotate makes a new data key the active one now, whatever the active one's age (spec 018: reseal -rotate, a
// data key that leaked). Another replica that rotated meanwhile made a new one too: that one is taken.
func (e *Envelope) Rotate(ctx context.Context) (string, error) {
	_, slot, err := e.keys.Active(ctx)
	if err != nil && !errors.Is(err, ErrNoDataKey) {
		return "", err
	}
	id, _, err := e.rotate(ctx, slot)
	if errors.Is(err, ErrKeyRace) {
		return e.ActiveID(ctx)
	}
	return id, err
}

// Retirement is a data key kept by Retire, and why.
type Retirement struct {
	ID     string
	Reason string // "" when retired
}

// Retire deletes the data keys nothing uses any more (spec 018): not the active one, superseded longer ago than
// a replica may keep one as its active one (the cache's TTL and a minute), and not in inUse - every row's data
// key, read after the rows were moved. A key that is neither active nor cached as active anywhere cannot come
// into use between that read and the delete.
func (e *Envelope) Retire(ctx context.Context, inUse map[string]bool) ([]Retirement, error) {
	active, _, err := e.keys.Active(ctx)
	if err != nil {
		return nil, err
	}
	all, err := e.keys.List(ctx)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(all, func(a, b DataKey) int { return a.CreatedAt.Compare(b.CreatedAt) })
	settled := e.now().Add(-(e.ttl + time.Minute))
	var out []Retirement
	for i, dk := range all {
		r := Retirement{ID: dk.ID}
		switch {
		case dk.ID == active.ID:
			continue
		case inUse[dk.ID]:
			r.Reason = "rows are still sealed under it"
		case i+1 == len(all) || all[i+1].CreatedAt.After(settled):
			r.Reason = "superseded too recently: a replica may still seal under it"
		default:
			deleted, err := e.keys.Delete(ctx, dk.ID)
			if err != nil {
				return out, err
			}
			if !deleted {
				r.Reason = "not deleted: it is the active one now, or gone"
			} else {
				e.mu.Lock()
				delete(e.cache, dk.ID)
				e.mu.Unlock()
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// SetClock replaces the envelope's clock (tests: a key superseded long ago).
func (e *Envelope) SetClock(now func() time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.now = now
}
