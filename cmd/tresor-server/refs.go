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
	"github.com/hugr-lab/tresor-server/internal/refscheck"
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	resolver, err := materialResolver(cfg)
	if err != nil {
		return err
	}
	// read-only: no migration, no lease beside the replica that serves (a SQLite store's), nothing created
	st, _, err := openState(ctx, cfg, log, true)
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

// checkRefs checks every secret's and variable's references, one line per finding on out; the number of
// findings, of entries read.
func checkRefs(ctx context.Context, st state.Store, r *material.Resolver, resolve bool, out io.Writer) (int, int, error) {
	n := 0
	checked, err := refscheck.Run(ctx, st, r, resolve, func(f refscheck.Finding) {
		fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", f.Kind, f.Name, f.Param, f.Reason)
		n++
	})
	return n, checked, err
}
