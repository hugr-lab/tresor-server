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
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	gcpkmsapi "cloud.google.com/go/kms/apiv1"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/api/option"

	"github.com/hugr-lab/tresor-server/internal/api"
	"github.com/hugr-lab/tresor-server/internal/audit"
	"github.com/hugr-lab/tresor-server/internal/auth"
	"github.com/hugr-lab/tresor-server/internal/awsid"
	"github.com/hugr-lab/tresor-server/internal/azure"
	"github.com/hugr-lab/tresor-server/internal/clientauth"
	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/gcpid"
	"github.com/hugr-lab/tresor-server/internal/health"
	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/keys/awskms"
	"github.com/hugr-lab/tresor-server/internal/keys/azurekeyvault"
	"github.com/hugr-lab/tresor-server/internal/keys/gcpkms"
	"github.com/hugr-lab/tresor-server/internal/keys/local"
	"github.com/hugr-lab/tresor-server/internal/keys/vaultkek"
	"github.com/hugr-lab/tresor-server/internal/kube"
	"github.com/hugr-lab/tresor-server/internal/material"
	"github.com/hugr-lab/tresor-server/internal/material/awssm"
	azkvsource "github.com/hugr-lab/tresor-server/internal/material/azurekeyvault"
	"github.com/hugr-lab/tresor-server/internal/material/gcpsm"
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
	"github.com/hugr-lab/tresor-server/web/console"
)

// version is the build's (-ldflags -X main.version=...): the image's tag.
var version = "dev"

// readyInterval is how often the readiness checks run (spec 002).
const readyInterval = 30 * time.Second

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	inv, err := parseArgs(os.Args[1:])
	if err != nil {
		log.Error("tresor-server: " + err.Error())
		os.Exit(2)
	}
	run := serve
	switch inv.command {
	case "rewrap":
		run = func(configPath string, log *slog.Logger) error { return rewrap(configPath, inv.tagUntagged, log) }
	case "refs":
		run = func(configPath string, log *slog.Logger) error { return refs(configPath, inv.resolve, os.Stdout, log) }
	case "mac":
		run = fillMACs
	case "reseal":
		run = func(configPath string, log *slog.Logger) error {
			return reseal(configPath, inv.rotate, inv.retire, log)
		}
	}
	if err := run(inv.configPath, log); err != nil {
		if errors.Is(err, errFindings) {
			log.Warn("tresor-server refs: " + err.Error())
			os.Exit(3)
		}
		log.Error("tresor-server "+inv.command+" stopped", "error", err.Error())
		os.Exit(1)
	}
}

// invocation is a command line, parsed.
type invocation struct {
	command, configPath  string
	tagUntagged, resolve bool
	rotate, retire       bool
}

// parseArgs reads [rewrap | refs | mac | reseal] and the flags; an error is a usage error (exit 2).
func parseArgs(args []string) (invocation, error) {
	inv := invocation{command: "serve"}
	if len(args) > 0 && (args[0] == "rewrap" || args[0] == "refs" || args[0] == "mac" || args[0] == "reseal") {
		inv.command, args = args[0], args[1:]
	}
	flags := flag.NewFlagSet("tresor-server "+inv.command, flag.ContinueOnError)
	flags.StringVar(&inv.configPath, "config", "", "the configuration file (optional: TRESOR_CONFIG and "+
		"TRESOR_<SETTING> variables are read over it)")
	switch inv.command {
	case "rewrap":
		flags.BoolVar(&inv.tagUntagged, "tag-untagged", false, "rewrap: tag the data keys that have no tag (made "+
			"before spec 003) - once, at the upgrade: you vouch for the store as it is")
	case "reseal":
		flags.BoolVar(&inv.rotate, "rotate", false, "reseal: a new active data key first (one that leaked: the rows "+
			"leave it too)")
		flags.BoolVar(&inv.retire, "retire", false, "reseal: then delete the data keys no row uses, superseded longer "+
			"than keys.cache_ttl ago")
	case "refs":
		flags.BoolVar(&inv.resolve, "resolve", false, "refs: read each admitted reference too, and list those that "+
			"do not resolve (the value is never printed)")
	}
	if err := flags.Parse(args); err != nil {
		return inv, err
	}
	if flags.NArg() > 0 {
		// `tresor-server -config x rewrap` must not start the service: the command comes first
		return inv, fmt.Errorf("unexpected arguments %q (usage: tresor-server [rewrap | refs | mac | reseal] -config <file>)", flags.Args())
	}
	return inv, nil
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
	st, _, err := openState(ctx, cfg, log, false)
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

// fillMACs gives every row of a SQL store with no MAC one (spec 014: tresor-server mac), once, after the
// upgrade and before state.mac is turned on: the operator vouches for the database as it is.
func fillMACs(configPath string, log *slog.Logger) error {
	cfg, _, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.State.Kind != "sqlite" && cfg.State.Kind != "postgres" && cfg.State.Kind != "sqlserver" {
		return fmt.Errorf("state.kind %s: tresor-server mac is for the SQL stores", cfg.State.Kind)
	}
	if cfg.State.Kind == "sqlite" {
		if _, err := os.Stat(cfg.State.Path); err != nil {
			return fmt.Errorf("state.path: %w", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg.State.MAC = false // the rows with none are read, to be filled
	st, _, err := openState(ctx, cfg, log, false)
	if err != nil {
		return err
	}
	defer st.Close()
	filled, skipped, err := st.(*sqlstore.Store).FillMACs(ctx)
	if errors.Is(err, state.ErrUnavailable) && cfg.State.Kind == "sqlite" {
		return errors.New("the SQLite database is held by a serving replica: stop the service, run tresor-server mac, start it")
	}
	if err != nil {
		return err
	}
	log.Info("rows given a MAC", "filled", filled, "skipped", skipped)
	if skipped > 0 {
		return fmt.Errorf("%d rows could not be given a MAC (named above): they are refused with state.mac: true", skipped)
	}
	log.Info("set state.mac: true now")
	return nil
}

// reseal moves every row to the active data key (spec 018: tresor-server reseal), a new one first with rotate,
// and with retire deletes the data keys nothing uses any more. It runs next to the service (every change is
// compare-and-set); on SQLite with the service stopped.
func reseal(configPath string, rotate, retire bool, log *slog.Logger) error {
	cfg, _, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if cfg.State.Kind == "sqlite" {
		if _, err := os.Stat(cfg.State.Path); err != nil {
			return fmt.Errorf("state.path: %w", err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st, _, err := openState(ctx, cfg, log, false)
	if err != nil {
		return err
	}
	defer st.Close()
	rs, ok := st.(state.Resealer)
	sealed, enveloped := st.(interface{ Envelope() *keys.Envelope })
	if !ok || !enveloped {
		return fmt.Errorf("state.kind %s keeps nothing at rest: nothing to reseal", cfg.State.Kind)
	}
	env := sealed.Envelope()
	// the store first, before anything is written (SQLite: a serving replica's lease)
	if _, err := rs.DataKeysInUse(ctx); err != nil {
		return unheld(cfg, err)
	}
	if rotate {
		id, err := env.Rotate(ctx)
		if err != nil {
			return unheld(cfg, err)
		}
		log.Info("a new active data key", "data_key", id)
	}
	moved, skipped, err := rs.Reseal(ctx)
	if err != nil {
		return unheld(cfg, err)
	}
	log.Info("rows moved to the active data key", "moved", moved, "skipped", skipped)
	if retire {
		inUse, err := rs.DataKeysInUse(ctx)
		if err != nil {
			return err
		}
		kept, err := env.Retire(ctx, inUse)
		n, left := 0, 0
		for _, k := range kept { // what was done, even when a delete then failed
			if k.Reason == "" {
				n++
				log.Info("a data key retired", "data_key", k.ID)
			} else {
				left++
				log.Warn("a data key kept", "data_key", k.ID, "reason", k.Reason)
			}
		}
		if err != nil {
			return err
		}
		log.Info("data keys retired", "count", n, "kept", left)
		if left > 0 {
			log.Warn("data keys are still stored: run tresor-server reseal -retire again once their reasons are past")
		}
	}
	if skipped > 0 {
		return fmt.Errorf("%d rows could not be moved (named above): their data keys are kept", skipped)
	}
	return nil
}

// unheld says what a SQLite store held by a serving replica means for a command.
func unheld(cfg *config.Config, err error) error {
	if errors.Is(err, state.ErrUnavailable) && cfg.State.Kind == "sqlite" {
		return errors.New("the SQLite database is held by a serving replica: stop the service, run the command, start it")
	}
	return err
}

// openState opens the configured store, and the readiness checks it brings (the KEK's). readOnly (refs, spec
// 009): a SQL store neither migrated nor leased; the Kubernetes store writes nothing at its open anyway.
func openState(ctx context.Context, cfg *config.Config, log *slog.Logger, readOnly bool) (state.Store, []health.Check, error) {
	switch cfg.State.Kind {
	case "memory":
		return memory.New(), nil, nil
	case "sqlite":
		wrapper, previous, err := keyWrapper(ctx, cfg)
		if err != nil {
			return nil, nil, err
		}
		st, err := sqlstore.OpenSQLite(ctx, cfg.State.Path, wrapper, sqlstore.Options{Log: log,
			Keys: keys.Options{DataKeyMaxAge: cfg.Keys.DataKeyMaxAge, CacheTTL: cfg.Keys.CacheTTL}, ReadOnly: readOnly, MAC: cfg.State.MAC})
		if err != nil {
			return nil, nil, err
		}
		return st, append([]health.Check{{Name: "keys", Run: st.Envelope().Check}}, previous...), nil
	case "postgres", "sqlserver":
		wrapper, previous, err := keyWrapper(ctx, cfg)
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
			Log: log, Keys: keys.Options{DataKeyMaxAge: cfg.Keys.DataKeyMaxAge, CacheTTL: cfg.Keys.CacheTTL}, ReadOnly: readOnly, MAC: cfg.State.MAC})
		if err != nil {
			return nil, nil, err
		}
		return st, append([]health.Check{{Name: "keys", Run: st.Envelope().Check}}, previous...), nil
	case "kubernetes":
		wrapper, previous, err := keyWrapper(ctx, cfg)
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
		return st, append([]health.Check{{Name: "keys", Run: st.Envelope().Check}}, previous...), nil
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
	if cfg.State.Auth == "gcp" {
		creds, err := gcpid.Credentials(context.Background(), cfg.GCP.StaticCredentials == "allow", sqlstore.ScopeCloudSQL)
		if err != nil {
			return nil, err
		}
		return sqlstore.GCPLogin{Tokens: creds.TokenSource}, nil
	}
	if cfg.State.Auth == "aws" {
		pc, err := pgconn.ParseConfig(cfg.State.DSN)
		if err != nil {
			return nil, errors.New("state.dsn does not parse") // pgconn's error may quote the DSN
		}
		if pc.TLSConfig == nil {
			return nil, errors.New("state.auth: aws needs TLS (sslmode=verify-full and the RDS CA): RDS takes an IAM token over TLS only")
		}
		ac, err := awsOf(cfg.AWS)
		if err != nil {
			return nil, err
		}
		return sqlstore.AWSLogin{Endpoint: net.JoinHostPort(pc.Host, strconv.Itoa(int(pc.Port))), Region: cfg.AWS.Region,
			User: pc.User, Credentials: ac.Credentials}, nil
	}
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
// one place (outside material's, config checks). Its source may be a named one (spec 008): that one's connection.
func passwordResolver(cfg *config.Config, ref string) (*material.Resolver, error) {
	scheme, rest, _ := strings.Cut(strings.TrimPrefix(ref, material.Prefix), "://")
	s, ok := cfg.Source(scheme)
	if !ok {
		return nil, fmt.Errorf("state.password_ref: no source is named %s", scheme)
	}
	switch s.Kind {
	case "k8s":
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
	case "vault":
		where, _, _ := strings.Cut(rest, "#")
		mount, path, _ := strings.Cut(where, "/")
		v, err := vaultOf(cfg, s)
		if err != nil {
			return nil, err
		}
		return checkedPassword(material.New(vaultkv.New(v, []vaultkv.Allow{{Mount: mount, Prefixes: []string{path}}}, 0).Named(s.Name)), ref)
	case "azkv":
		parts := strings.Split(rest, "/")
		if len(parts) < 2 {
			return nil, fmt.Errorf("state.password_ref: ref+%s://<vault>/<secret>[/<version>]", s.Name)
		}
		cred, err := azureOf(s.Azure)
		if err != nil {
			return nil, err
		}
		return checkedPassword(material.New(azkvsource.New([]azkvsource.Allow{{Vault: parts[0], Prefixes: []string{parts[1]}}}, cred,
			azkvsource.Options{DNSSuffix: s.AzKV.DNSSuffix}).Named(s.Name)), ref)
	case "aws":
		name, _, _ := strings.Cut(rest, "?")
		name, _, _ = strings.Cut(name, "#")
		if name == "" {
			return nil, fmt.Errorf("state.password_ref: ref+%s://<secret>[#<field>]", s.Name)
		}
		ac, err := awsOf(s.AWS)
		if err != nil {
			return nil, err
		}
		// that one reference only: the allowlist is its name, and the resolver resolves nothing else
		return checkedPassword(material.New(awssm.New(secretsmanager.NewFromConfig(ac), []string{name}, false, 0).Named(s.Name)), ref)
	case "gcp":
		parts := strings.Split(rest, "/")
		if len(parts) < 2 {
			return nil, fmt.Errorf("state.password_ref: ref+%s://<project>/<secret>[/<version>]", s.Name)
		}
		if _, err := checkedPassword(material.New(gcpsm.New(nil, []gcpsm.Allow{{Project: parts[0], Prefixes: []string{parts[1]}}}, 0).Named(s.Name)), ref); err != nil {
			return nil, err // before reaching for the API
		}
		sm, err := gcpSecrets(cfg)
		if err != nil {
			return nil, err
		}
		return material.New(gcpsm.New(sm, []gcpsm.Allow{{Project: parts[0], Prefixes: []string{parts[1]}}}, 0).Named(s.Name)), nil
	}
	return nil, fmt.Errorf("state.password_ref: a %s source", s.Kind)
}

// checkedPassword: the password reference parses, at start - not at the first connection.
func checkedPassword(r *material.Resolver, ref string) (*material.Resolver, error) {
	if !r.Admits(ref) {
		return nil, errors.New("state.password_ref does not parse: ref+k8s://<namespace>/<secret>/<key>, " +
			"ref+azkv://<vault>/<secret>[/<version>], ref+vault://<mount>/<path>#<field>, ref+aws://<secret>[#<field>] or ref+gcp://<project>/<secret>[/<version>] (or a named source's)")
	}
	return r, nil
}

// azureOf is an identity's credential.
func azureOf(a config.Azure) (azcore.TokenCredential, error) {
	return azure.Credential(azure.Identity{Kind: a.Identity, ClientID: a.ClientID, TenantID: a.TenantID})
}

// vaultOf is a source's Vault client: the process's own for the top-level vault:, one of its own for a named
// source's vault: block (spec 008).
func vaultOf(cfg *config.Config, s config.Source) (*vault.Client, error) {
	if !s.OwnConnection {
		return vaultClient(cfg)
	}
	return newVaultClient(s.Vault)
}

// materialResolver is where references may read (material:), or nil: then every reference is refused.
func materialResolver(cfg *config.Config) (*material.Resolver, error) {
	var sources []material.Source
	for _, s := range cfg.Sources() {
		switch s.Kind {
		case "azkv":
			cred, err := azureOf(s.Azure)
			if err != nil {
				return nil, fmt.Errorf("material (%s): %w", s.Name, err)
			}
			allow := make([]azkvsource.Allow, len(s.AzKV.Allow))
			for i, a := range s.AzKV.Allow {
				allow[i] = azkvsource.Allow{Vault: a.Vault, Prefixes: a.Prefixes}
			}
			sources = append(sources, traced.Source(azkvsource.New(allow, cred,
				azkvsource.Options{DNSSuffix: s.AzKV.DNSSuffix, CacheTTL: s.AzKV.CacheTTL}).Named(s.Name)))
		case "k8s":
			// the service's own namespace holds its own credentials (a local KEK, a password, a client secret):
			// never readable by a reference
			if own, err := kube.Namespace(cfg.State.Namespace); err == nil {
				for _, a := range s.K8s.Allow {
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
			allow := make([]k8ssource.Allow, len(s.K8s.Allow))
			for i, a := range s.K8s.Allow {
				allow[i] = k8ssource.Allow{Namespace: a.Namespace, Prefixes: a.Prefixes}
			}
			src, err := k8ssource.New(allow, rc)
			if err != nil {
				return nil, err
			}
			sources = append(sources, traced.Source(src))
		case "vault":
			v, err := vaultOf(cfg, s)
			if err != nil {
				return nil, fmt.Errorf("material (%s): %w", s.Name, err)
			}
			allow := make([]vaultkv.Allow, len(s.VaultAllow.Allow))
			for i, a := range s.VaultAllow.Allow {
				allow[i] = vaultkv.Allow{Mount: a.Mount, Prefixes: a.Prefixes}
			}
			sources = append(sources, traced.Source(vaultkv.New(v, allow, s.VaultAllow.CacheTTL).Named(s.Name)))
		case "aws":
			ac, err := awsOf(s.AWS)
			if err != nil {
				return nil, fmt.Errorf("material (%s): %w", s.Name, err)
			}
			prefixes, all := s.AWSAllow.Prefixes()
			sources = append(sources, traced.Source(awssm.New(secretsmanager.NewFromConfig(ac), prefixes, all, s.AWSAllow.CacheTTL).Named(s.Name)))
		case "gcp":
			sm, err := gcpSecrets(cfg)
			if err != nil {
				return nil, fmt.Errorf("material (%s): %w", s.Name, err)
			}
			allow := make([]gcpsm.Allow, len(s.GCPAllow.Allow))
			for i, a := range s.GCPAllow.Allow {
				allow[i] = gcpsm.Allow{Project: a.Project, Prefixes: a.Prefixes}
			}
			sources = append(sources, traced.Source(gcpsm.New(sm, allow, s.GCPAllow.CacheTTL).Named(s.Name)))
		}
	}
	if len(sources) == 0 {
		return nil, nil
	}
	return material.New(sources...), nil
}

// keyWrapper is the configured KEK, traced (spec 005).
// keyWrapper is the configured KEK, chained with the previous ones (spec 011: they unwrap, never wrap), traced;
// and a readiness check per previous KEK - values under it would not open while it does not answer.
func keyWrapper(ctx context.Context, cfg *config.Config) (keys.KeyWrapper, []health.Check, error) {
	current, err := kekOf(cfg, cfg.Keys.Current())
	if err != nil {
		return nil, nil, err
	}
	var previous []keys.KeyWrapper
	var checks []health.Check
	for i, p := range cfg.Keys.Previous {
		w, err := kekOf(cfg, p)
		if err != nil {
			return nil, nil, fmt.Errorf("keys.previous[%d]: %w", i, err)
		}
		previous = append(previous, w)
		// a round trip, not a cached id: the root needs the operation data keys under it are checked with
		// (Transit's hmac, Key Vault's sign), so a previous KEK the service may not use is not ready
		checks = append(checks, health.Check{Name: fmt.Sprintf("keys.previous[%d]", i), Run: func(ctx context.Context) error {
			id, err := w.Current(ctx)
			if err == nil {
				_, err = w.Root(ctx, id)
			}
			return err
		}})
	}
	// bounded: a KEK that does not answer is not judged here (readiness reports it), and must not hold the start
	// past the liveness probe; a duplicate missed then is still refused at its first unwrap (two owners)
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := keys.Distinct(dctx, current, previous...); err != nil {
		return nil, nil, err
	}
	return traced.Wrapper(keys.Chain(current, previous...)), checks, nil
}

func kekOf(cfg *config.Config, k config.KEK) (keys.KeyWrapper, error) {
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
	case k.Kind == "awskms":
		ac, err := awsOf(cfg.AWS)
		if err != nil {
			return nil, err
		}
		return awskms.New(kms.NewFromConfig(ac), k.Key, k.MacKey)
	case k.Kind == "gcpkms":
		c, err := gcpKMS(cfg)
		if err != nil {
			return nil, err
		}
		return gcpkms.New(c, k.Key, k.MacKey)
	}
	return nil, fmt.Errorf("keys.kind %s is not built in", k.Kind)
}

// previousKEKs names the previous KEKs for the console: their kind and where they are, never key material.
func previousKEKs(cfg *config.Config) []map[string]string {
	out := []map[string]string{}
	for _, p := range cfg.Keys.Previous {
		where := p.Key
		switch {
		case p.Kind == "vault":
			where = p.Mount + "/" + p.Key
		case p.KeyFile != "":
			where = "file " + p.KeyFile
		case p.KeyEnv != "":
			where = "variable " + p.KeyEnv
		}
		out = append(out, map[string]string{"kind": p.Kind, "key": where})
	}
	return out
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

	st, stateChecks, err := openState(ctx, cfg, log, false)
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
	// every source of the kind: another may admit the same place, on the same server or vault (spec 008)
	if ref := cfg.State.PasswordRef; ref != "" {
		scheme, where, _ := strings.Cut(strings.TrimPrefix(ref, material.Prefix), "://")
		s, ok := cfg.Source(scheme)
		if !ok {
			return fmt.Errorf("state.password_ref: no source is named %s", scheme)
		}
		if resolver.AdmitsPlace(s.Kind, where) {
			return errors.New("state.password_ref is within material's allowlist: an administrator could read the database's password")
		}
	}
	level, err := audit.ParseLevel(cfg.Audit.Level)
	if err != nil {
		return err
	}
	exchange, exchangeChecks, err := exchangeAuth(ctx, cfg)
	if err != nil {
		return err
	}
	opts := []api.Option{api.WithMaterial(resolver), api.WithAudit(audit.New(level, os.Stdout)),
		api.WithExchangeAuth(exchange)}
	var checker *health.Checker // made below: the console asks it at each request
	if cfg.UI.On() {
		c := api.Console{UI: consoleHandler(cfg), Version: version,
			Ready: func() (bool, map[string]string) { return checker.Ready() }}
		if sealed, ok := st.(interface{ Envelope() *keys.Envelope }); ok {
			c.KEK = sealed.Envelope().Current
			c.PreviousKEKs = previousKEKs(cfg)
		}
		opts = append(opts, api.WithConsole(c))
	}
	srv, err := api.New(ctx, cfg, verifier, traced.Store(st), log, opts...)
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
	checker = health.New(log, readyInterval, checks...)
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

// consoleHandler serves the console's build (spec 010), told how people sign in: the issuers with a public client.
func consoleHandler(cfg *config.Config) http.Handler {
	c := console.Config{API: strings.TrimRight(cfg.PublicURL, "/"), Environment: cfg.UI.Environment,
		FrameAncestors: cfg.UI.FrameAncestors, ConnectSrc: cfg.UI.ConnectSrc}
	if u, err := url.Parse(cfg.PublicURL); err == nil {
		c.BasePath = strings.TrimRight(u.Path, "/")
	}
	for _, is := range cfg.Issuers {
		if is.ClientID != "" {
			c.Issuers = append(c.Issuers, console.Issuer{Issuer: is.Issuer, ClientID: is.ClientID, Scopes: is.Scopes,
				Audience: is.Audience, AudienceParameter: is.AudienceParameter})
		}
	}
	return console.Handler(c)
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
		case "vault":
			v, err := vaultClient(cfg)
			if err != nil {
				return nil, nil, err
			}
			mount, key, _ := strings.Cut(ex.Key, "/")
			signer, err := vaultkek.NewSigner(ctx, v, mount, key)
			if err != nil {
				return nil, nil, err
			}
			source = clientauth.JWT(clientID, clientauth.Header{KID: ex.KID, X5T: ex.X5T}, aud, signer)
		case "awskms":
			ac, err := awsOf(cfg.AWS)
			if err != nil {
				return nil, nil, err
			}
			signer, err := awskms.NewSigner(ctx, kms.NewFromConfig(ac), ex.Key)
			if err != nil {
				return nil, nil, err
			}
			source = clientauth.JWT(clientID, clientauth.Header{KID: ex.KID, X5T: ex.X5T}, aud, signer)
		case "gcpkms":
			c, err := gcpKMS(cfg)
			if err != nil {
				return nil, nil, err
			}
			signer, err := gcpkms.NewSigner(ctx, c, ex.Key)
			if err != nil {
				return nil, nil, err
			}
			source = clientauth.JWT(clientID, clientauth.Header{KID: ex.KID, X5T: ex.X5T}, aud, signer)
		}
		out[config.IssuerKey(is.Issuer)] = mint.AssertionAuth{ID: clientID, Assertion: source, OmitID: ex.OmitClientID}
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

// awsConfigs are the SDK configurations made, one per identity (the top-level aws:, a named source's own): one
// credentials cache each, shared by the KEK, references, the database and signing.
var awsConfigs struct {
	sync.Mutex
	made map[config.AWS]aws.Config
}

// awsOf is an identity's SDK configuration (spec 012): the platform's identity, never a static key unless allowed.
func awsOf(a config.AWS) (aws.Config, error) {
	awsConfigs.Lock()
	defer awsConfigs.Unlock()
	if c, ok := awsConfigs.made[a]; ok {
		return c, nil
	}
	c, err := awsid.Config(context.Background(), awsid.Identity{Region: a.Region, EndpointURL: a.EndpointURL,
		StaticCredentials: a.StaticCredentials == "allow", RoleARN: a.RoleARN}, slog.Default())
	if err != nil {
		return aws.Config{}, err
	}
	if awsConfigs.made == nil {
		awsConfigs.made = map[config.AWS]aws.Config{}
	}
	awsConfigs.made[a] = c
	return c, nil
}

// gcpClients are the process's Cloud KMS and Secret Manager clients (spec 012): one each, with the service's GCP
// identity (Application Default Credentials, found for each), shared by the KEK, signing and references.
var gcpClients struct {
	sync.Mutex
	kms *gcpkmsapi.KeyManagementClient
	sm  *secretmanager.Client
}

func gcpOptions(cfg *config.Config) ([]option.ClientOption, error) {
	creds, err := gcpid.Credentials(context.Background(), cfg.GCP.StaticCredentials == "allow")
	if err != nil {
		return nil, err
	}
	// pinned: the universe never comes from the environment
	return []option.ClientOption{option.WithCredentials(creds), option.WithUniverseDomain(gcpid.Universe)}, nil
}

func gcpKMS(cfg *config.Config) (*gcpkmsapi.KeyManagementClient, error) {
	gcpClients.Lock()
	defer gcpClients.Unlock()
	if gcpClients.kms == nil {
		opts, err := gcpOptions(cfg)
		if err != nil {
			return nil, err
		}
		if gcpClients.kms, err = gcpkmsapi.NewKeyManagementClient(context.Background(), opts...); err != nil {
			return nil, fmt.Errorf("the Cloud KMS client: %w", err)
		}
	}
	return gcpClients.kms, nil
}

func gcpSecrets(cfg *config.Config) (*secretmanager.Client, error) {
	gcpClients.Lock()
	defer gcpClients.Unlock()
	if gcpClients.sm == nil {
		opts, err := gcpOptions(cfg)
		if err != nil {
			return nil, err
		}
		if gcpClients.sm, err = secretmanager.NewClient(context.Background(), opts...); err != nil {
			return nil, fmt.Errorf("the Secret Manager client: %w", err)
		}
	}
	return gcpClients.sm, nil
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
	c, err := newVaultClient(cfg.Vault)
	if err != nil {
		return nil, err
	}
	vaultOnce.client = c
	return c, nil
}

func newVaultClient(v config.Vault) (*vault.Client, error) {
	return vault.New(vault.Config{Address: v.Address, Namespace: v.Namespace, CAFile: v.CAFile,
		Auth: vault.Auth{Method: v.Auth.Method, Mount: v.Auth.Mount, Role: v.Auth.Role, JWTFile: v.Auth.JWTFile,
			TokenFile: v.Auth.TokenFile}})
}
