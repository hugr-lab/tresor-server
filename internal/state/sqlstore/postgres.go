package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/keys"
)

var sslModeKey = regexp.MustCompile(`(?i)(?:^|\s)sslmode\s*=\s*'?([a-z-]+)`)

// sslMode is a DSN's sslmode, "" when it names none (pgx then prefers TLS and falls back to plain text).
func sslMode(dsn string) string {
	if u, err := url.Parse(dsn); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Query().Get("sslmode")
	}
	if m := sslModeKey.FindStringSubmatch(dsn); m != nil {
		return m[1]
	}
	return ""
}

// OpenPostgres opens a PostgreSQL database (spec 002): several replicas. The DSN names the server, the
// database and the user, never a password: login gives it, for each new connection - an Entra token on
// Azure Database for PostgreSQL.
func OpenPostgres(ctx context.Context, dsn string, login Login, maxOpen int, wrapper keys.KeyWrapper, opts Options) (*Store, error) {
	if dsnHasPassword(dsn) {
		return nil, errors.New("state.dsn: a DSN carries no password - it comes from state.auth")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("state.dsn: not a PostgreSQL DSN") // its text may hold what it should not
	}
	// the password - an Entra token - goes over this connection: off this machine, only over TLS with the
	// server's certificate checked (pgx's default, prefer, falls back to plain text; require checks nothing)
	if !config.IsLoopback(cfg.Host) && sslMode(dsn) != "verify-full" {
		return nil, errors.New("state.dsn: sslmode=verify-full is required for a server off this machine")
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	db := stdlib.OpenDB(*cfg, stdlib.OptionBeforeConnect(func(ctx context.Context, cc *pgx.ConnConfig) error {
		pw, err := login.Password(ctx)
		if err != nil {
			return err
		}
		cc.Password = pw
		return nil
	}))
	if maxOpen <= 0 {
		maxOpen = 10 // a small server (Burstable B1ms) has few connections to give
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxOpen)
	db.SetConnMaxLifetime(30 * time.Minute) // a connection's token expires; a new one logs in afresh
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("state: the PostgreSQL database: %w", err)
	}
	s, err := open(ctx, db, Postgres, wrapper, opts)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("state: %w", err)
	}
	return s, nil
}
