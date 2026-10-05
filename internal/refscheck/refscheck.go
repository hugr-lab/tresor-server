// Package refscheck finds the stored references the configuration would not resolve (spec 009): every
// secret's and variable's ref+... parameters against the sources, as at a fetch - and, asked to, a read of each.
// The command (tresor-server refs) and the console (spec 010) run it. No value is kept or reported.
package refscheck

import (
	"context"
	"errors"
	"fmt"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/material"
	"github.com/hugr-lab/tresor-server/internal/state"
)

// Finding is one reference that would not resolve, or an entry that does not open: Param "-" then.
type Finding struct {
	Kind   string `json:"kind"` // secret, variable
	Name   string `json:"name"`
	Param  string `json:"param"`
	Reason string `json:"reason"` // the source's error: it names a reference only once it parsed
}

// Run checks every secret and variable in st against r, reporting each finding to found as it comes; the number
// of entries read. Only a sealed entry is a finding: any other error of the store or the KEK, or the context's
// end, stops the run - an outage is no finding.
func Run(ctx context.Context, st state.Store, r *material.Resolver, resolve bool, found func(Finding)) (int, error) {
	checked := 0
	for _, ns := range []struct {
		kind  string
		store state.Store
	}{{"secret", st}, {"variable", st.Variables()}} {
		list, err := ns.store.List(ctx)
		if err != nil {
			return checked, fmt.Errorf("%ss: %w", ns.kind, err)
		}
		for _, d := range list {
			sec, err := ns.store.Get(ctx, d.Name)
			if errors.Is(err, state.ErrNotFound) {
				continue // deleted meanwhile
			}
			if ctx.Err() != nil {
				return checked, ctx.Err() // stopped: what is left is unread, not a finding
			}
			checked++
			if errors.Is(err, keys.ErrSealed) {
				// this one's value does not open: a finding, not a stop - the others are still worth reading
				found(Finding{Kind: ns.kind, Name: d.Name, Param: "-", Reason: "does not open: " + err.Error()})
				continue
			}
			if err != nil {
				return checked, fmt.Errorf("%s %s: %w", ns.kind, d.Name, err) // the store or the KEK: an error
			}
			findings := r.Check(ctx, sec.Params, resolve)
			if ctx.Err() != nil {
				return checked, ctx.Err()
			}
			for _, f := range findings {
				found(Finding{Kind: ns.kind, Name: d.Name, Param: f.Param, Reason: f.Err.Error()})
			}
		}
	}
	return checked, nil
}
