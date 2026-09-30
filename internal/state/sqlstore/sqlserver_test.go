package sqlstore

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"strings"
	"testing"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/hugr-lab/tresor-server/internal/state"
	"github.com/hugr-lab/tresor-server/internal/state/statetest"
)

// SQL Server runs when a server is given (CI: a service container):
//
//	TRESOR_TEST_SQLSERVER=sqlserver://sa@127.0.0.1:51433?encrypt=disable
//	TRESOR_TEST_SQLSERVER_PASSWORD=...
//
// Each test gets a database of its own, dropped after it.
func sqlserverDB(t *testing.T) string {
	t.Helper()
	admin := os.Getenv("TRESOR_TEST_SQLSERVER")
	if admin == "" {
		t.Skip("TRESOR_TEST_SQLSERVER names no SQL Server")
	}
	cfg, err := msdsn.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Password = os.Getenv("TRESOR_TEST_SQLSERVER_PASSWORD")
	db := sql.OpenDB(mssql.NewConnectorConfig(cfg))
	t.Cleanup(func() { db.Close() })
	raw := make([]byte, 6)
	_, _ = rand.Read(raw)
	name := "tresor_test_" + hex.EncodeToString(raw)
	if _, err := db.Exec(`CREATE DATABASE ` + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`ALTER DATABASE ` + name + ` SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE ` + name)
	})
	u, _ := url.Parse(admin)
	q := u.Query()
	q.Set("database", name)
	u.RawQuery = q.Encode()
	return u.String()
}

func openSQLServer(t *testing.T, dsn string) *Store {
	t.Helper()
	s, err := OpenSQLServer(ctx, dsn, PasswordLogin{Env: "TRESOR_TEST_SQLSERVER_PASSWORD"}, 8, kek(t, 1), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSQLServer(t *testing.T) {
	statetest.Run(t, func(t *testing.T) statetest.Handles {
		dsn := sqlserverDB(t)
		first := openSQLServer(t, dsn)
		return statetest.Handles{First: first, Replicas: true, Another: func() state.Store { return openSQLServer(t, dsn) }}
	})
}

// replicas starting at once migrate the database once
func TestSQLServerConcurrentMigrations(t *testing.T) {
	dsn := sqlserverDB(t)
	errs := make(chan error, 4)
	for range 4 {
		go func() {
			s, err := OpenSQLServer(ctx, dsn, PasswordLogin{Env: "TRESOR_TEST_SQLSERVER_PASSWORD"}, 2, kek(t, 1), Options{})
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

// off this machine the login goes only encrypted, with the server's certificate checked
func TestSQLServerRequiresVerifiedTLS(t *testing.T) {
	for _, dsn := range []string{"sqlserver://corp.database.windows.net?database=d",
		"sqlserver://corp.database.windows.net?database=d&encrypt=true&trustservercertificate=true",
		"sqlserver://corp.database.windows.net?database=d&encrypt=disable"} {
		_, err := OpenSQLServer(ctx, dsn, PasswordLogin{Env: "X"}, 1, kek(t, 1), Options{})
		if err == nil || !strings.Contains(err.Error(), "encrypt") {
			t.Errorf("%s: %v", dsn, err)
		}
	}
	if _, err := OpenSQLServer(ctx, "sqlserver://sa:x@h?database=d", PasswordLogin{Env: "X"}, 1, kek(t, 1), Options{}); err == nil {
		t.Fatal("a password in the DSN")
	}
}
