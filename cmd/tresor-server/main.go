// tresor-server is the production duckdb-secrets/1 service (spec 001, spec 002). It started from tresor's
// reference server (tresor specs/003, MIT, the same owner).
//
//	tresor-server -config server.yaml
//	TRESOR_LISTEN=0.0.0.0:8080 TRESOR_STATE__KIND=memory ... tresor-server
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hugr-lab/tresor-server/internal/api"
	"github.com/hugr-lab/tresor-server/internal/auth"
	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/health"
	"github.com/hugr-lab/tresor-server/internal/state"
	"github.com/hugr-lab/tresor-server/internal/state/memory"
)

// readyInterval is how often the readiness checks run (spec 002).
const readyInterval = 30 * time.Second

func main() {
	configPath := flag.String("config", "", "the configuration file (optional: TRESOR_CONFIG and TRESOR_<SETTING> "+
		"variables are read over it)")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*configPath, log); err != nil {
		log.Error("tresor-server stopped", "error", err.Error())
		os.Exit(1)
	}
}

func openState(cfg config.State) (state.Store, error) {
	switch cfg.Kind {
	case "memory":
		return memory.New(), nil
	}
	return nil, fmt.Errorf("state.kind %q is not built in", cfg.Kind)
}

func run(configPath string, log *slog.Logger) error {
	cfg, fromEnv, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if len(fromEnv) > 0 {
		log.Info("configuration from the environment", "variables", fromEnv) // names, never values
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := openState(cfg.State)
	if err != nil {
		return err
	}
	defer st.Close()
	verifier := auth.NewVerifier(cfg.Issuers)
	srv, err := api.New(ctx, cfg, verifier, st, log)
	if err != nil {
		return err
	}
	checks := []health.Check{{Name: "state", Run: st.Ping}}
	for _, iss := range verifier.Issuers() {
		checks = append(checks, health.Check{
			Name: "issuer " + iss,
			Run:  func(ctx context.Context) error { return verifier.CheckIssuer(ctx, iss) },
			Soft: func() bool { return verifier.Answered(iss) },
		})
	}
	checker := health.New(log, readyInterval, checks...)
	checker.Start(ctx)

	mux := http.NewServeMux()
	checker.Register(mux) // outside the protocol's routes, and outside public_url's path
	mux.Handle("/", srv.Handler())
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Info("tresor-server listening", "listen", listener.Addr().String(), "api", cfg.PublicURL,
		"tls", cfg.TLS.Cert != "", "state", cfg.State.Kind)

	errs := make(chan error, 1)
	go func() {
		if cfg.TLS.Cert != "" {
			errs <- server.ServeTLS(listener, cfg.TLS.Cert, cfg.TLS.Key)
		} else {
			errs <- server.Serve(listener)
		}
	}()
	select {
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		checker.Drain() // unready first: the platform stops sending requests here
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
