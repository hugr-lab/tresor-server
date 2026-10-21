package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hugr-lab/tresor-server/internal/state"
	"github.com/hugr-lab/tresor-server/internal/vault"
	"github.com/hugr-lab/tresor-server/internal/vault/vaulttest"
)

// a lease's credentials serve new connections until one made with them could outlive the lease; then new ones
func TestVaultLoginRotation(t *testing.T) {
	now := time.Now()
	n := 0
	l := &VaultLogin{Now: func() time.Time { return now }, Fetch: func(context.Context) (VaultCredentials, error) {
		n++
		return VaultCredentials{User: "v-" + string(rune('a'+n)), Password: "pw", Lease: time.Hour}, nil
	}}
	u1, _, err := l.Credentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(27 * time.Minute) // a connection made now ends at 57 min: within the lease
	if u, _, _ := l.Credentials(context.Background()); u != u1 || n != 1 {
		t.Fatalf("kept: %s %d", u, n)
	}
	now = now.Add(2 * time.Minute) // at 29 min one could outlive it (29+30+2 > 60): new credentials
	if u, _, _ := l.Credentials(context.Background()); u == u1 || n != 2 {
		t.Fatalf("renewed: %s %d", u, n)
	}
	short := &VaultLogin{Now: time.Now, Fetch: func(context.Context) (VaultCredentials, error) {
		return VaultCredentials{User: "u", Password: "p", Lease: 20 * time.Minute}, nil
	}}
	if _, _, err := short.Credentials(context.Background()); err == nil || !strings.Contains(err.Error(), "default_ttl") {
		t.Fatalf("a lease shorter than a connection: %v", err)
	}
	failing := &VaultLogin{Now: time.Now, Fetch: func(context.Context) (VaultCredentials, error) {
		return VaultCredentials{}, errors.New("permission denied")
	}}
	if _, _, err := failing.Credentials(context.Background()); err == nil {
		t.Fatal("no credentials: no error")
	}
}

// the store on PostgreSQL with a database secrets engine's credentials (spec 027), on every Vault server given -
// TRESOR_TEST_VAULT_DB_HOST names PostgreSQL as the Vault servers reach it (CI: postgres:5432, the services' network)
func TestPostgresVaultLogin(t *testing.T) {
	host := os.Getenv("TRESOR_TEST_VAULT_DB_HOST")
	if host == "" {
		t.Skip("TRESOR_TEST_VAULT_DB_HOST names no PostgreSQL the Vault servers reach")
	}
	dsn := postgresDB(t)
	u, _ := url.Parse(dsn)
	dbName := strings.TrimPrefix(u.Path, "/")
	pgPassword := os.Getenv("TRESOR_TEST_POSTGRES_PASSWORD")
	// the group role every lease's user is granted: it owns the tables (state.vault.set_role)
	owner := "owner_" + dbName
	admin, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin.Password = pgPassword
	adb := stdlib.OpenDB(*admin)
	defer adb.Close()
	for _, q := range []string{`CREATE ROLE "` + owner + `" NOLOGIN`, `GRANT ALL ON DATABASE "` + dbName + `" TO "` + owner + `"`,
		`GRANT ALL ON SCHEMA public TO "` + owner + `"`} {
		if _, err := adb.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = adb.Exec(`DROP OWNED BY "` + owner + `"; DROP ROLE IF EXISTS "` + owner + `"`) })
	for _, srv := range vaulttest.Servers(t) {
		t.Run(srv.Name, func(t *testing.T) {
			mount := srv.Mount(t, "database")
			srv.Call(t, "POST", mount+"/config/pg", map[string]any{
				"plugin_name":    "postgresql-database-plugin",
				"connection_url": "postgresql://{{username}}:{{password}}@" + host + "/" + dbName + "?sslmode=disable",
				"username":       "postgres", "password": pgPassword, "allowed_roles": "tresor",
				"verify_connection": true,
			}, nil)
			srv.Call(t, "POST", mount+"/roles/tresor", map[string]any{
				"db_name":             "pg",
				"creation_statements": []string{`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE "` + owner + `";`},
				"default_ttl":         "1h", "max_ttl": "2h",
			}, nil)
			client, err := vault.New(vault.Config{Address: srv.Address, Auth: vault.Auth{Method: "token_file", TokenFile: srv.TokenFile(t)}})
			if err != nil {
				t.Fatal(err)
			}
			newLogin := func() *VaultLogin {
				return &VaultLogin{Now: time.Now, Fetch: func(ctx context.Context) (VaultCredentials, error) {
					var out struct {
						LeaseDuration int64                               `json:"lease_duration"`
						Data          struct{ Username, Password string } `json:"data"`
					}
					if err := client.Do(ctx, "GET", mount+"/creds/tresor", nil, &out); err != nil {
						return VaultCredentials{}, err
					}
					return VaultCredentials{User: out.Data.Username, Password: out.Data.Password,
						Lease: time.Duration(out.LeaseDuration) * time.Second}, nil
				}}
			}
			// the DSN names no user: the engine's is taken
			noUser := *u
			noUser.User = nil
			first := newLogin()
			s, err := OpenPostgres(ctx, noUser.String(), first, 4, kek(t, 1), Options{MAC: true, SetRole: owner})
			if err != nil {
				t.Fatal(err)
			}
			user, _, _ := first.Credentials(ctx)
			var who, role string
			if err := s.db.QueryRowContext(ctx, `SELECT session_user, current_user`).Scan(&who, &role); err != nil ||
				who != user || role != owner {
				t.Fatalf("logged in as %q (%q), the engine's %q: %v", who, role, user, err)
			}
			statetestCreate(t, s, "kept")
			s.Close()
			// a later lease: another user, the same tables (the group role owns them)
			second := newLogin()
			s2, err := OpenPostgres(ctx, noUser.String(), second, 4, kek(t, 1), Options{MAC: true, SetRole: owner})
			if err != nil {
				t.Fatal(err)
			}
			defer s2.Close()
			if u2, _, _ := second.Credentials(ctx); u2 == user {
				t.Fatal("the same user for another lease")
			}
			if got, err := s2.Get(ctx, "kept"); err != nil || got.Name != "kept" {
				t.Fatalf("a later lease's user reads what the first wrote: %v", err)
			}
		})
	}
}

// statetestCreate writes one secret.
func statetestCreate(t *testing.T, st state.Store, name string) {
	t.Helper()
	if _, err := st.Update(ctx, name, func(*state.Secret) (*state.Secret, error) {
		return &state.Secret{Name: name, Type: "s3", Provider: "config", Params: map[string]json.RawMessage{"k": json.RawMessage(`"v"`)}, Version: 1}, nil
	}); err != nil {
		t.Fatal(err)
	}
}
