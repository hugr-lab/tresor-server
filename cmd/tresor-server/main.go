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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hugr-lab/tresor-server/internal/api"
	"github.com/hugr-lab/tresor-server/internal/audit"
	"github.com/hugr-lab/tresor-server/internal/auth"
	"github.com/hugr-lab/tresor-server/internal/azure"
	"github.com/hugr-lab/tresor-server/internal/clientauth"
	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/health"
	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/keys/azurekeyvault"
	"github.com/hugr-lab/tresor-server/internal/keys/local"
	"github.com/hugr-lab/tresor-server/internal/keys/vaultkek"
	"github.com/hugr-lab/tresor-server/internal/kube"
	"github.com/hugr-lab/tresor-server/internal/material"
	azkvsource "github.com/hugr-lab/tresor-server/internal/material/azurekeyvault"
	k8ssource "github.com/hugr-lab/tresor-server/internal/material/k8s"
	"github.com/hugr-lab/tresor-server/internal/material/vaultkv"
	"github.com/hugr-lab/tresor-server/internal/mint"
	"github.com/hugr-lab/tresor-server/internal/state"
	"github.com/hugr-lab/tresor-server/internal/state/kubestore"
	"github.com/hugr-lab/tresor-server/internal/state/memory"
	"github.com/hugr-lab/tresor-server/internal/state/sqlstore"
	"github.com/hugr-lab/tresor-server/internal/telemetry"
	"github.com/hugr-lab/tresor-server/internal/traced"
	"github.com/hugr-lab/tresor-server/internal/vault"
)

// version is the build's (-ldflags -X main.version=...): the image's tag.
var version = "dev"

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
	tagUntagged := false
	if command == "rewrap" {
		flags.BoolVar(&tagUntagged, "tag-untagged", false, "rewrap: tag the data keys that have no tag (made before "+
			"spec 003) - once, at the upgrade: you vouch for the store as it is")
	}
	_ = flags.Parse(args)
	if flags.NArg() > 0 {
		// `tresor-server -config x rewrap` must not start the service: the command comes first
		log.Error("tresor-server: unexpected arguments (usage: tresor-server [rewrap] -config <file>)",
			"arguments", flags.Args())
		os.Exit(2)
	}
	run := serve
	if command == "rewrap" {
		run = func(configPath string, log *slog.Logger) error { return rewrap(configPath, tagUntagged, log) }
	}
	if err := run(*configPath, log); err != nil {
		log.Error("tresor-server "+command+" stopped", "error", err.Error())
		os.Exit(1)
	}
}

// rewrap wraps every data key under the KEK's current version (spec 002): after a rotation of the KEK, its
// old versions can then be retired. No sealed value is touched. It runs next to the service, whose data keys
// it changes compare-and-set.
func rewrap(configPath string, tagUntagged bool, log *slog.Logger) error {
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
	n, err := sealed.Envelope().Rewrap(ctx, tagUntagged, func(id string) {
		log.Warn("a data key with no tag was tagged (--tag-untagged)", "data_key", id)
	})
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
	case "postgres", "sqlserver":
		wrapper, err := keyWrapper(cfg)
		if err != nil {
			return nil, nil, err
		}
		open, scope := sqlstore.OpenPostgres, sqlstore.ScopePostgres
		if cfg.State.Kind == "sqlserver" {
			open, scope = sqlstore.OpenSQLServer, sqlstore.ScopeSQLServer
		}
		login, err := databaseLogin(cfg, scope)
		if err != nil {
			return nil, nil, err
		}
		st, err := open(ctx, cfg.State.DSN, login, cfg.State.MaxOpenConns, wrapper, sqlstore.Options{
			Log: log, Keys: keys.Options{DataKeyMaxAge: cfg.Keys.DataKeyMaxAge, CacheTTL: cfg.Keys.CacheTTL}})
		if err != nil {
			return nil, nil, err
		}
		return st, []health.Check{{Name: "keys", Run: st.Envelope().Check}}, nil
	case "kubernetes":
		wrapper, err := keyWrapper(cfg)
		if err != nil {
			return nil, nil, err
		}
		rc, err := kube.Config()
		if err != nil {
			return nil, nil, err
		}
		ns, err := kube.Namespace(cfg.State.Namespace)
		if err != nil {
			return nil, nil, err
		}
		st, err := kubestore.Open(ctx, rc, wrapper, kubestore.Options{Namespace: ns, Instance: cfg.State.Instance, Log: log,
			Keys: keys.Options{DataKeyMaxAge: cfg.Keys.DataKeyMaxAge, CacheTTL: cfg.Keys.CacheTTL}})
		if err != nil {
			return nil, nil, err
		}
		log.Info("state in the Kubernetes API", "namespace", ns)
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
	if ref := cfg.State.PasswordRef; ref != "" {
		r, err := passwordResolver(cfg, ref)
		if err != nil {
			return nil, err
		}
		return sqlstore.RefLogin{Resolve: func(ctx context.Context) (string, error) { return r.ResolveOne(ctx, ref) }}, nil
	}
	return sqlstore.PasswordLogin{Env: cfg.State.PasswordEnv, File: cfg.State.PasswordFile}, nil
}

// passwordResolver reads the database's password reference, and nothing else: its source's allowlist is that
// one place (outside material's, config checks).
func passwordResolver(cfg *config.Config, ref string) (*material.Resolver, error) {
	if rest, ok := strings.CutPrefix(ref, "ref+k8s://"); ok {
		parts := strings.Split(rest, "/")
		if len(parts) != 3 {
			return nil, errors.New("state.password_ref: ref+k8s://<namespace>/<secret>/<key>")
		}
		allow := []k8ssource.Allow{{Namespace: parts[0], Prefixes: []string{parts[1]}}}
		if _, err := checkedPassword(material.New(k8ssource.NewWithGetter(allow, nil)), ref); err != nil {
			return nil, err // before reaching for the API
		}
		rc, err := kube.Config()
		if err != nil {
			return nil, err
		}
		src, err := k8ssource.New(allow, rc)
		if err != nil {
			return nil, err
		}
		return material.New(src), nil
	}
	if rest, ok := strings.CutPrefix(ref, "ref+vault://"); ok {
		where, _, _ := strings.Cut(rest, "#")
		mount, path, _ := strings.Cut(where, "/")
		v, err := vaultClient(cfg)
		if err != nil {
			return nil, err
		}
		return checkedPassword(material.New(vaultkv.New(v, []vaultkv.Allow{{Mount: mount, Prefixes: []string{path}}}, 0)), ref)
	}
	rest := strings.TrimPrefix(ref, "ref+azkv://")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return nil, errors.New("state.password_ref: ref+azkv://<vault>/<secret>[/<version>]")
	}
	cred, err := azure.Credential(azure.Identity{Kind: cfg.Azure.Identity, ClientID: cfg.Azure.ClientID})
	if err != nil {
		return nil, err
	}
	return checkedPassword(material.New(azkvsource.New([]azkvsource.Allow{{Vault: parts[0], Prefixes: []string{parts[1]}}}, cred,
		azkvsource.Options{DNSSuffix: cfg.Material.AzKV.DNSSuffix})), ref)
}

// checkedPassword: the password reference parses, at start - not at the first connection.
func checkedPassword(r *material.Resolver, ref string) (*material.Resolver, error) {
	if !r.Admits(ref) {
		return nil, errors.New("state.password_ref does not parse: ref+k8s://<namespace>/<secret>/<key>, " +
			"ref+azkv://<vault>/<secret>[/<version>] or ref+vault://<mount>/<path>#<field>")
	}
	return r, nil
}

// materialResolver is where references may read (material:), or nil: then every reference is refused.
func materialResolver(cfg *config.Config) (*material.Resolver, error) {
	var sources []material.Source
	if kv := cfg.Material.AzKV; len(kv.Allow) > 0 {
		cred, err := azure.Credential(azure.Identity{Kind: cfg.Azure.Identity, ClientID: cfg.Azure.ClientID})
		if err != nil {
			return nil, err
		}
		allow := make([]azkvsource.Allow, len(kv.Allow))
		for i, a := range kv.Allow {
			allow[i] = azkvsource.Allow{Vault: a.Vault, Prefixes: a.Prefixes}
		}
		sources = append(sources, traced.Source(azkvsource.New(allow, cred, azkvsource.Options{DNSSuffix: kv.DNSSuffix, CacheTTL: kv.CacheTTL})))
	}
	if k := cfg.Material.K8s; len(k.Allow) > 0 {
		// the service's own namespace holds its own credentials (a local KEK, a password, a client secret):
		// never readable by a reference
		if own, err := kube.Namespace(cfg.State.Namespace); err == nil {
			for _, a := range k.Allow {
				if a.Namespace == own {
					return nil, fmt.Errorf("material.k8s.allow names %s, the service's own namespace: its credentials are "+
						"there - keep the Secrets references read in another", own)
				}
			}
		}
		rc, err := kube.Config()
		if err != nil {
			return nil, err
		}
		allow := make([]k8ssource.Allow, len(k.Allow))
		for i, a := range k.Allow {
			allow[i] = k8ssource.Allow{Namespace: a.Namespace, Prefixes: a.Prefixes}
		}
		src, err := k8ssource.New(allow, rc)
		if err != nil {
			return nil, err
		}
		sources = append(sources, traced.Source(src))
	}
	if mv := cfg.Material.Vault; len(mv.Allow) > 0 {
		v, err := vaultClient(cfg)
		if err != nil {
			return nil, err
		}
		allow := make([]vaultkv.Allow, len(mv.Allow))
		for i, a := range mv.Allow {
			allow[i] = vaultkv.Allow{Mount: a.Mount, Prefixes: a.Prefixes}
		}
		sources = append(sources, traced.Source(vaultkv.New(v, allow, mv.CacheTTL)))
	}
	if len(sources) == 0 {
		return nil, nil
	}
	return material.New(sources...), nil
}

// keyWrapper is the configured KEK, traced (spec 005).
func keyWrapper(cfg *config.Config) (keys.KeyWrapper, error) {
	w, err := kekOf(cfg)
	if err != nil {
		return nil, err
	}
	return traced.Wrapper(w), nil
}

func kekOf(cfg *config.Config) (keys.KeyWrapper, error) {
	k := cfg.Keys
	switch {
	case k.Kind == "local" && k.KeyEnv != "":
		return local.FromEnv(k.KeyEnv)
	case k.Kind == "local":
		return local.FromFile(k.KeyFile)
	case k.Kind == "vault":
		v, err := vaultClient(cfg)
		if err != nil {
			return nil, err
		}
		return vaultkek.New(v, k.Mount, k.Key)
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
	// spec 005: OpenTelemetry from the environment (nothing exported without an endpoint); flushed at the end
	flush, err := telemetry.Setup(ctx, telemetry.Options{Version: version, Traces: cfg.Telemetry.TracesOn()})
	if err != nil {
		return err
	}
	defer func() {
		done, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := flush(done); err != nil {
			log.Warn("telemetry was not flushed", "error", err.Error())
		}
	}()

	st, stateChecks, err := openState(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer st.Close()
	verifier := auth.NewVerifier(cfg.Issuers)
	resolver, err := materialResolver(cfg)
	if err != nil {
		return err
	}
	// the sources' own parse, beside config's: the database's password is no administrator's to read
	if ref := cfg.State.PasswordRef; ref != "" && resolver != nil && resolver.Admits(ref) {
		return errors.New("state.password_ref is within material's allowlist: an administrator could read the database's password")
	}
	level, err := audit.ParseLevel(cfg.Audit.Level)
	if err != nil {
		return err
	}
	exchange, exchangeChecks, err := exchangeAuth(ctx, cfg)
	if err != nil {
		return err
	}
	srv, err := api.New(ctx, cfg, verifier, traced.Store(st), log, api.WithMaterial(resolver),
		api.WithAudit(audit.New(level, os.Stdout)), api.WithExchangeAuth(exchange))
	if err != nil {
		return err
	}
	checks := append([]health.Check{{Name: "state", Run: st.Ping}}, stateChecks...)
	checks = append(checks, exchangeChecks...)
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
	log.Info("tresor-server listening", "version", version, "listen", listener.Addr().String(), "api", cfg.PublicURL,
		"tls", cfg.TLS.Cert != "", "tls_offload", cfg.TLS.Offload, "state", cfg.State.Kind)

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

// exchangeAuth is how the service logs in at each issuer's token endpoint with no client secret (spec 006),
// by IssuerKey, and a readiness check per issuer that makes an assertion - degraded, not unready, when it
// fails: only token_exchange secrets depend on it. An issuer with client_auth: secret is not in it.
func exchangeAuth(ctx context.Context, cfg *config.Config) (map[string]mint.ClientAuth, []health.Check, error) {
	out := map[string]mint.ClientAuth{}
	var checks []health.Check
	for _, is := range cfg.Issuers {
		ex := is.Exchange
		if ex == nil || ex.ClientAuth == "secret" {
			continue
		}
		clientID := ex.ClientID
		var source clientauth.Source
		aud := clientauth.Audience{Issuer: is.Issuer, TokenEndpoint: ex.AssertionAudience == "token_endpoint"}
		switch ex.ClientAuth {
		case "azure":
			cred, err := azure.Credential(azure.Identity{Kind: cfg.Azure.Identity, ClientID: cfg.Azure.ClientID})
			if err != nil {
				return nil, nil, err
			}
			source = clientauth.Azure(cred)
		case "file":
			source = clientauth.File(ex.AssertionFile)
		case "key_file":
			signer, kid, fileClient, err := clientauth.KeyFile(ex.KeyFile)
			if err != nil {
				return nil, nil, err
			}
			if ex.KID != "" {
				if kid != "" && kid != ex.KID {
					return nil, nil, fmt.Errorf("exchange.kid is not the key file's keyId")
				}
				kid = ex.KID
			}
			if kid == "" && ex.X5T == "" {
				return nil, nil, fmt.Errorf("exchange.kid: the key file names no keyId - set kid (or x5t)")
			}
			if fileClient != "" {
				if clientID != "" && clientID != fileClient {
					return nil, nil, fmt.Errorf("exchange.client_id is not the key file's clientId")
				}
				clientID = fileClient
			}
			if clientID == "" {
				return nil, nil, fmt.Errorf("exchange.client_id: the key file names no clientId - set client_id")
			}
			source = clientauth.JWT(clientID, clientauth.Header{KID: kid, X5T: ex.X5T}, aud, signer)
		case "keyvault":
			cred, err := azure.Credential(azure.Identity{Kind: cfg.Azure.Identity, ClientID: cfg.Azure.ClientID})
			if err != nil {
				return nil, nil, err
			}
			signer, err := azurekeyvault.NewSigner(ctx, ex.Key, cred)
			if err != nil {
				return nil, nil, err
			}
			source = clientauth.JWT(clientID, clientauth.Header{KID: ex.KID, X5T: ex.X5T}, aud, signer)
		}
		out[config.IssuerKey(is.Issuer)] = mint.AssertionAuth{ID: clientID, Assertion: source}
		checks = append(checks, health.Check{
			Name: "exchange " + is.Issuer,
			Run: func(ctx context.Context) error {
				_, err := source(ctx, "")
				return err
			},
			Soft: func() bool { return true },
		})
	}
	return out, checks, nil
}

// vaultOnce is the process's one Vault client (spec 007): one login, shared by the KEK, references and signing.
var vaultOnce struct {
	sync.Mutex
	client *vault.Client
}

func vaultClient(cfg *config.Config) (*vault.Client, error) {
	vaultOnce.Lock()
	defer vaultOnce.Unlock()
	if vaultOnce.client != nil {
		return vaultOnce.client, nil
	}
	v := cfg.Vault
	c, err := vault.New(vault.Config{Address: v.Address, Namespace: v.Namespace, CAFile: v.CAFile,
		Auth: vault.Auth{Method: v.Auth.Method, Mount: v.Auth.Mount, Role: v.Auth.Role, JWTFile: v.Auth.JWTFile,
			TokenFile: v.Auth.TokenFile}})
	if err != nil {
		return nil, err
	}
	vaultOnce.client = c
	return c, nil
}
