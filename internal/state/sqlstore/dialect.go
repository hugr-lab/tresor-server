package sqlstore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	mssql "github.com/microsoft/go-mssqldb"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

//go:embed migrations
var migrations embed.FS

// Dialect is what differs between the databases (spec 002): the driver, the placeholders, the migrations'
// DDL, which errors mean what, how a transaction takes a lock, and whether the database allows several
// writers.
type Dialect struct {
	Name string
	// Rebind turns a query written with `?` into the database's placeholders.
	Rebind func(query string) string
	// Unique says whether err is a unique (or primary key) violation: another writer created the row first.
	Unique func(err error) bool
	// ForeignKey says whether err is a foreign key violation: the row it names is gone.
	ForeignKey func(err error) bool
	// Retryable says whether err is the database giving up on a transaction that may simply be run again:
	// a deadlock, a serialization failure. Nothing was written.
	Retryable func(err error) bool
	// Lock takes an exclusive lock named key until tx ends: the migrations of replicas starting at once, an
	// actor's grants counted and inserted. (SQLite: its write transactions are exclusive already.)
	Lock func(ctx context.Context, tx *sql.Tx, key string) error
	// Bootstrap makes the table the migrations are recorded in, if missing.
	Bootstrap string
	// SingleWriter: one replica only, held by the lease row (SQLite).
	SingleWriter bool
}

const bootstrapPortable = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version BIGINT NOT NULL PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)`

// SQLite is modernc.org/sqlite: pure Go, one writer.
var SQLite = Dialect{
	Name:   "sqlite",
	Rebind: func(q string) string { return q },
	Unique: func(err error) bool {
		var se *sqlite.Error
		if !errors.As(err, &se) {
			return false
		}
		return se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || se.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
	},
	ForeignKey: func(err error) bool {
		var se *sqlite.Error
		return errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY
	},
	Retryable:    func(error) bool { return false }, // busy_timeout waits; immediate transactions do not deadlock
	Lock:         func(context.Context, *sql.Tx, string) error { return nil },
	Bootstrap:    bootstrapPortable,
	SingleWriter: true,
}

// Postgres is PostgreSQL through pgx: several replicas.
var Postgres = Dialect{
	Name:       "postgres",
	Rebind:     numbered("$"),
	Unique:     pgCode("23505"),
	ForeignKey: pgCode("23503"),
	Retryable:  pgCode("40001", "40P01"), // serialization failure, deadlock
	Lock: func(ctx context.Context, tx *sql.Tx, key string) error {
		_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key)
		return err
	},
	Bootstrap: bootstrapPortable,
}

// SQLServer is SQL Server or Azure SQL through go-mssqldb: several replicas.
var SQLServer = Dialect{
	Name:       "sqlserver",
	Rebind:     numbered("@p"),
	Unique:     msNumber(2627, 2601, 2714), // a unique constraint, a unique index; an object that exists (the bootstrap)
	ForeignKey: msNumber(547),
	Retryable:  msNumber(1205, 51205), // a deadlock victim; sp_getapplock's own (below)
	Lock: func(ctx context.Context, tx *sql.Tx, key string) error {
		_, err := tx.ExecContext(ctx, `DECLARE @r INT;
			EXEC @r = sp_getapplock @Resource = @p1, @LockMode = 'Exclusive', @LockOwner = 'Transaction', @LockTimeout = 30000;
			IF @r = -3 THROW 51205, 'sp_getapplock: chosen as a deadlock victim', 1;
			IF @r < 0 THROW 50000, 'sp_getapplock did not give the lock', 1;`, key)
		return err
	},
	Bootstrap: `IF OBJECT_ID(N'schema_migrations', N'U') IS NULL
		CREATE TABLE schema_migrations (version BIGINT NOT NULL PRIMARY KEY, name NVARCHAR(400) NOT NULL,
			applied_at BIGINT NOT NULL)`,
}

func msNumber(numbers ...int32) func(error) bool {
	return func(err error) bool {
		var me mssql.Error
		if !errors.As(err, &me) {
			return false
		}
		for _, n := range numbers {
			if me.SQLErrorNumber() == n {
				return true
			}
		}
		return false
	}
}

// numbered rebinds `?` to prefix1, prefix2, ... (the queries hold no `?` of their own).
func numbered(prefix string) func(string) string {
	return func(q string) string {
		var b strings.Builder
		n := 0
		for _, r := range q {
			if r == '?' {
				n++
				b.WriteString(prefix + strconv.Itoa(n))
				continue
			}
			b.WriteRune(r)
		}
		return b.String()
	}
}

func pgCode(codes ...string) func(error) bool {
	return func(err error) bool {
		var pe *pgconn.PgError
		if !errors.As(err, &pe) {
			return false
		}
		for _, c := range codes {
			if pe.Code == c {
				return true
			}
		}
		return false
	}
}
