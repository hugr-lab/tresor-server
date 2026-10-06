package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/keys"
)

// a move to another KEK end to end (spec 011): a secret written under the old local KEK; the new one as keys
// with the old as keys.previous - the secret reads, rewrap moves the data keys; then the new KEK alone reads it;
// the old KEK repeated as keys is refused at start
func TestMoveToAnotherKEK(t *testing.T) {
	dir := t.TempDir()
	key := func(name string, b byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	oldKEK, newKEK := key("old", 1), key("new", 2)
	db := filepath.Join(dir, "t.db")
	path := filepath.Join(dir, "server.yaml")
	write := func(keysDoc string) *config.Config {
		t.Helper()
		doc := "listen: 127.0.0.1:8443\npublic_url: http://127.0.0.1:8443\nstate: {kind: sqlite, path: " + db + "}\n" + keysDoc +
			"issuers: [{issuer: 'http://127.0.0.1:18080/realms/t', audience: duckdb-secrets}]\npolicy: {admins: [role:secrets_admin]}\n"
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, _, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	read := func(cfg *config.Config) error {
		st, _, err := openState(ctx, cfg, log, false)
		if err != nil {
			return err
		}
		defer st.Close()
		sec, err := st.Get(ctx, "pg")
		if err == nil && !strings.Contains(string(sec.Params["password"]), "hunter2") {
			t.Fatalf("read back: %s", sec.Params["password"])
		}
		return err
	}

	cfg := write("keys: {kind: local, key_file: " + oldKEK + "}\n")
	st, _, err := openState(ctx, cfg, log, false)
	if err != nil {
		t.Fatal(err)
	}
	put(t, st, "pg", `{"password":"hunter2"}`)
	st.Close()

	moving := "keys: {kind: local, key_file: " + newKEK + ", previous: [{kind: local, key_file: " + oldKEK + "}]}\n"
	cfg = write(moving)
	if err := read(cfg); err != nil {
		t.Fatalf("under the new KEK with the old one previous: %v", err)
	}
	open, checks, err := openState(ctx, cfg, log, false)
	if err != nil || len(checks) != 2 || checks[1].Name != "keys.previous[0]" || checks[1].Run(ctx) != nil {
		t.Fatalf("readiness: %v %+v", err, checks)
	}
	open.Close()
	if err := rewrap(path, false, log); err != nil {
		t.Fatal(err)
	}

	alone := write("keys: {kind: local, key_file: " + newKEK + "}\n")
	if err := read(alone); err != nil {
		t.Fatalf("the new KEK alone, after rewrap: %v", err)
	}
	// the old KEK alone no longer opens it: fail closed
	if err := read(write("keys: {kind: local, key_file: " + oldKEK + "}\n")); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("the old KEK alone, after rewrap: %v", err)
	}
	// the same key as keys and previous (another file, the same bytes): refused at start
	same := key("same", 2)
	if st, _, err := openState(ctx, write("keys: {kind: local, key_file: "+newKEK+", previous: [{kind: local, key_file: "+same+"}]}\n"), log, false); err == nil ||
		!strings.Contains(err.Error(), "same KEK") {
		if st != nil {
			st.Close()
		}
		t.Fatalf("the same KEK twice: %v", err)
	}
}
