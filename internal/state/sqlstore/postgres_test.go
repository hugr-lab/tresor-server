package sqlstore

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hugr-lab/tresor-server/internal/state"
	"github.com/hugr-lab/tresor-server/internal/state/statetest"
)

// PostgreSQL runs when a server is given (CI: a service container):
//
//	TRESOR_TEST_POSTGRES=postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable
//	TRESOR_TEST_POSTGRES_PASSWORD=...
//
// Each test gets a database of its own, dropped after it.
func postgresDB(t *testing.T) string {
	t.Helper()
	admin := os.Getenv("TRESOR_TEST_POSTGRES")
	if admin == "" {
		t.Skip("TRESOR_TEST_POSTGRES names no PostgreSQL server")
	}
	cfg, err := pgx.ParseConfig(admin)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Password = os.Getenv("TRESOR_TEST_POSTGRES_PASSWORD")
	db := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { db.Close() })
	raw := make([]byte, 6)
	_, _ = rand.Read(raw)
	name := "tresor_test_" + hex.EncodeToString(raw)
	if _, err := db.Exec(`CREATE DATABASE ` + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DROP DATABASE ` + name + ` WITH (FORCE)`) })
	u, _ := url.Parse(admin)
	u.Path = "/" + name
	return u.String()
}

func openPostgres(t *testing.T, dsn string, db *sql.DB) *Store {
	t.Helper()
	s, err := OpenPostgres(ctx, dsn, PasswordLogin{Env: "TRESOR_TEST_POSTGRES_PASSWORD"}, 8, kek(t, 1), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestPostgres(t *testing.T) {
	statetest.Run(t, func(t *testing.T) statetest.Handles {
		dsn := postgresDB(t)
		first := openPostgres(t, dsn, nil)
		// several replicas: another handle serves side by side
		return statetest.Handles{First: first, Replicas: true, Another: func() state.Store { return openPostgres(t, dsn, nil) }}
	})
}

// replicas starting at once migrate the database once
func TestPostgresConcurrentMigrations(t *testing.T) {
	dsn := postgresDB(t)
	errs := make(chan error, 4)
	for range 4 {
		go func() {
			s, err := OpenPostgres(ctx, dsn, PasswordLogin{Env: "TRESOR_TEST_POSTGRES_PASSWORD"}, 2, kek(t, 1), Options{})
			if err == nil {
				s.Close()
			}
			errs <- err
		}()
	}
	for range 4 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestPostgresRefusesAPasswordInTheDSN(t *testing.T) {
	for _, dsn := range []string{"postgres://u:secret@h/db", "host=h user=u password=secret dbname=db",
		"postgres://u@h/db?password=secret"} {
		if _, err := OpenPostgres(ctx, dsn, PasswordLogin{Env: "X"}, 1, kek(t, 1), Options{}); err == nil ||
			!dsnHasPassword(dsn) {
			t.Errorf("%s: accepted", dsn)
		}
	}
}

// off this machine the password (an Entra token) goes only over TLS with the certificate checked
func TestPostgresRequiresVerifiedTLS(t *testing.T) {
	for _, dsn := range []string{"host=db.example user=u dbname=d", "host=db.example user=u dbname=d sslmode=require",
		"postgres://u@db.example/d?sslmode=prefer", "postgres://u@db.example/d"} {
		_, err := OpenPostgres(ctx, dsn, PasswordLogin{Env: "X"}, 1, kek(t, 1), Options{})
		if err == nil || !strings.Contains(err.Error(), "verify-full") {
			t.Errorf("%s: %v", dsn, err)
		}
	}
	if sslMode("host=db user=u sslmode = 'verify-full'") != "verify-full" || sslMode("postgres://u@h/d?sslmode=verify-full") != "verify-full" {
		t.Fatal("sslmode not read")
	}
}

// replicas starting at once on an empty database: every one opens it (the migrations' table made under the
// lock: CREATE TABLE IF NOT EXISTS alone races in the catalog)
func TestPostgresReplicasStartTogether(t *testing.T) {
	for range 5 {
		dsn := postgresDB(t)
		errs := make(chan error, 6)
		for range cap(errs) {
			go func() {
				s, err := OpenPostgres(ctx, dsn, PasswordLogin{Env: "TRESOR_TEST_POSTGRES_PASSWORD"}, 2, kek(t, 1), Options{})
				if err == nil {
					s.Close()
				}
				errs <- err
			}()
		}
		for range cap(errs) {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		}
	}
}
