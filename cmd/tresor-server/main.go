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
	"github.com/hugr-lab/tresor-server/internal/azure"
	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/health"
	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/keys/azurekeyvault"
	"github.com/hugr-lab/tresor-server/internal/keys/local"
	"github.com/hugr-lab/tresor-server/internal/state"
	"github.com/hugr-lab/tresor-server/internal/state/memory"
	"github.com/hugr-lab/tresor-server/internal/state/sqlstore"
)

// readyInterval is how often the readiness checks run (spec 002).
const readyInterval = 30 * time.Second

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	command, args := "serve", os.Args[1:]
	if len(args) > 0 && args[0] == "rewrap" {
		command, args = "rewrap", args[1:]
	}
	flags := flag.NewFlagSet("tresor-server "+command, flag.ExitOnError)
	configPath := flags.String("config", "", "the configuration file (optional: TRESOR_CONFIG and TRESOR_<SETTING> "+
		"variables are read over it)")
	_ = flags.Parse(args)
	if flags.NArg() > 0 {
		// `tresor-server -config x rewrap` must not start the service: the command comes first
		log.Error("tresor-server: unexpected arguments (usage: tresor-server [rewrap] -config <file>)",
			"arguments", flags.Args())
		os.Exit(2)
	}
	run := serve
	if command == "rewrap" {
		run = rewrap
	}
	if err := run(*configPath, log); err != nil {
		log.Error("tresor-server "+command+" stopped", "error", err.Error())
		os.Exit(1)
	}
}

// rewrap wraps every data key under the KEK's current version (spec 002): after a rotation of the KEK, its
// old versions can then be retired. No sealed value is touched. It runs next to the service, whose data keys
// it changes compare-and-set.
func rewrap(configPath string, log *slog.Logger) error {
	cfg, _, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.State.Kind == "sqlite" {
		// a wrong path must not create an empty database
		if _, err := os.Stat(cfg.State.Path); err != nil {
			return fmt.Errorf("state.path: %w", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st, _, err := openState(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer st.Close()
	sealed, ok := st.(interface{ Envelope() *keys.Envelope })
	if !ok {
		return fmt.Errorf("state.kind %s keeps nothing at rest: nothing to rewrap", cfg.State.Kind)
	}
	n, err := sealed.Envelope().Rewrap(ctx)
	if err != nil {
		return err
	}
	log.Info("data keys rewrapped under the KEK's current version", "count", n)
	return nil
}

// openState opens the configured store, and the readiness checks it brings (the KEK's).
func openState(ctx context.Context, cfg *config.Config, log *slog.Logger) (state.Store, []health.Check, error) {
	switch cfg.State.Kind {
	case "memory":
		return memory.New(), nil, nil
	case "sqlite":
		wrapper, err := keyWrapper(cfg)
		if err != nil {
			return nil, nil, err
		}
		st, err := sqlstore.OpenSQLite(ctx, cfg.State.Path, wrapper, sqlstore.Options{Log: log,
			Keys: keys.Options{DataKeyMaxAge: cfg.Keys.DataKeyMaxAge, CacheTTL: cfg.Keys.CacheTTL}})
		if err != nil {
			return nil, nil, err
		}
		return st, []health.Check{{Name: "keys", Run: st.Envelope().Check}}, nil
	case "postgres":
		wrapper, err := keyWrapper(cfg)
		if err != nil {
			return nil, nil, err
		}
		login, err := databaseLogin(cfg, sqlstore.ScopePostgres)
		if err != nil {
			return nil, nil, err
		}
		st, err := sqlstore.OpenPostgres(ctx, cfg.State.DSN, login, cfg.State.MaxOpenConns, wrapper, sqlstore.Options{
			Log: log, Keys: keys.Options{DataKeyMaxAge: cfg.Keys.DataKeyMaxAge, CacheTTL: cfg.Keys.CacheTTL}})
		if err != nil {
			return nil, nil, err
		}
		return st, []health.Check{{Name: "keys", Run: st.Envelope().Check}}, nil
	}
	return nil, nil, fmt.Errorf("state.kind %s is not built in", cfg.State.Kind)
}

// purgeGrants removes expired delegation grants, with their sealed tokens, every minute: nothing of a grant
// stays at rest past its expiry.
func purgeGrants(ctx context.Context, st state.Store, log *slog.Logger) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := st.Delegations().Purge(ctx, time.Now()); err != nil && !errors.Is(err, state.ErrUnavailable) {
				log.Warn("expired delegation grants were not purged", "error", err.Error())
			}
		}
	}
}

// databaseLogin is how the service logs in to its database server: an Entra token, or a password.
func databaseLogin(cfg *config.Config, scope string) (sqlstore.Login, error) {
	if cfg.State.Auth == "entra" {
		cred, err := azure.Credential(azure.Identity{Kind: cfg.Azure.Identity, ClientID: cfg.Azure.ClientID})
		if err != nil {
			return nil, err
		}
		return sqlstore.EntraLogin{Credential: cred, Scope: scope}, nil
	}
	return sqlstore.PasswordLogin{Env: cfg.State.PasswordEnv, File: cfg.State.PasswordFile}, nil
}

// keyWrapper is the configured KEK.
func keyWrapper(cfg *config.Config) (keys.KeyWrapper, error) {
	k := cfg.Keys
	switch {
	case k.Kind == "local" && k.KeyEnv != "":
		return local.FromEnv(k.KeyEnv)
	case k.Kind == "local":
		return local.FromFile(k.KeyFile)
	case k.Kind == "azurekeyvault":
		cred, err := azure.Credential(azure.Identity{Kind: cfg.Azure.Identity, ClientID: cfg.Azure.ClientID})
		if err != nil {
			return nil, err
		}
		return azurekeyvault.New(k.Key, cred)
	}
	return nil, fmt.Errorf("keys.kind %s is not built in", k.Kind)
}

func serve(configPath string, log *slog.Logger) error {
	cfg, fromEnv, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if len(fromEnv) > 0 {
		log.Info("configuration from the environment", "variables", fromEnv) // names, never values
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, stateChecks, err := openState(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer st.Close()
	verifier := auth.NewVerifier(cfg.Issuers)
	srv, err := api.New(ctx, cfg, verifier, st, log)
	if err != nil {
		return err
	}
	checks := append([]health.Check{{Name: "state", Run: st.Ping}}, stateChecks...)
	for _, iss := range verifier.Issuers() {
		checks = append(checks, health.Check{
			Name: "issuer " + iss,
			Run:  func(ctx context.Context) error { return verifier.CheckIssuer(ctx, iss) },
			Soft: func() bool { return verifier.Answered(iss) },
		})
	}
	checker := health.New(log, readyInterval, checks...)
	checker.Start(ctx)
	go purgeGrants(ctx, st, log)

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
