package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/material"
	"github.com/hugr-lab/tresor-server/internal/state"
)

// errFindings: references the configuration would not resolve were found (exit 3).
var errFindings = errors.New("references that would not resolve")

// refs lists the stored references the configuration does not admit, or (resolve) that do not resolve (spec
// 009): one line per finding on out, no value ever.
func refs(configPath string, resolve bool, out io.Writer, log *slog.Logger) error {
	cfg, _, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.State.Kind == "memory" {
		return fmt.Errorf("state.kind memory keeps nothing: no reference to check")
	}
	if cfg.State.Kind == "sqlite" {
		// a wrong path must not create an empty database
		if _, err := os.Stat(cfg.State.Path); err != nil {
			return fmt.Errorf("state.path: %w", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	resolver, err := materialResolver(cfg)
	if err != nil {
		return err
	}
	st, _, err := openState(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer st.Close()
	n, checked, err := checkRefs(ctx, st, resolver, resolve, out)
	if err != nil {
		return err
	}
	log.Info("references checked", "entries", checked, "findings", n)
	if n > 0 {
		return errFindings
	}
	return nil
}

// checkRefs checks every secret's and variable's references; the number of findings, of entries read.
func checkRefs(ctx context.Context, st state.Store, r *material.Resolver, resolve bool, out io.Writer) (int, int, error) {
	n, checked := 0, 0
	for _, ns := range []struct {
		kind  string
		store state.Store
	}{{"secret", st}, {"variable", st.Variables()}} {
		list, err := ns.store.List(ctx)
		if err != nil {
			return n, checked, fmt.Errorf("%ss: %w", ns.kind, err)
		}
		for _, d := range list {
			sec, err := ns.store.Get(ctx, d.Name)
			if errors.Is(err, state.ErrNotFound) {
				continue // deleted meanwhile
			}
			checked++
			if err != nil {
				// sealed, or the KEK's answer: a finding, not a stop - the others are still worth reading
				fmt.Fprintf(out, "%s\t%s\t-\tdoes not open: %v\n", ns.kind, d.Name, err)
				n++
				continue
			}
			for _, f := range r.Check(ctx, sec.Params, resolve) {
				fmt.Fprintf(out, "%s\t%s\t%s\t%v\n", ns.kind, d.Name, f.Param, f.Err)
				n++
			}
		}
	}
	return n, checked, nil
}
