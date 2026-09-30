package sqlstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hugr-lab/tresor-server/internal/keys"
)

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
	db := stdlib.OpenDB(*cfg, stdlib.OptionBeforeConnect(func(ctx context.Context, cc *pgx.ConnConfig) error {
		pw, err := login.Password(ctx)
		if err != nil {
			return err
		}
		cc.Password = pw
		return nil
	}))
	if maxOpen > 0 {
		db.SetMaxOpenConns(maxOpen)
		db.SetMaxIdleConns(maxOpen)
	}
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
