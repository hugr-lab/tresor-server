package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/material"
	"github.com/hugr-lab/tresor-server/internal/state"
	"github.com/hugr-lab/tresor-server/internal/state/memory"
)

// kv resolves ref+kv://<name> within allow; a name not in values does not resolve
type kv struct {
	allow  string
	values map[string]string
}

func (kv) Scheme() string { return "kv" }
func (kv) Kind() string   { return "kv" }
func (s kv) Parse(text string) (material.Ref, error) {
	if !strings.HasPrefix(text, s.allow) {
		return material.Ref{}, errors.New("ref+kv://" + text + " is outside the allowlist")
	}
	return material.Ref{Scheme: "kv", Vault: "v", Name: text}, nil
}
func (s kv) Resolve(_ context.Context, ref material.Ref) (string, string, error) {
	if v, ok := s.values[ref.Name]; ok {
		return v, "1", nil
	}
	return "", "", errors.New("no such secret")
}

// sealedStore answers one secret as sealed
type sealedStore struct {
	state.Store
	name string
}

func (s sealedStore) Get(ctx context.Context, name string) (*state.Secret, error) {
	if name == s.name {
		return nil, keys.ErrSealed
	}
	return s.Store.Get(ctx, name)
}

func put(t *testing.T, st state.Store, name, params string) {
	t.Helper()
	var p map[string]json.RawMessage
	if err := json.Unmarshal([]byte(params), &p); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Update(context.Background(), name, func(*state.Secret) (*state.Secret, error) {
		return &state.Secret{Name: name, Type: "s3", Provider: "config", Params: p, Version: 1}, nil
	}); err != nil {
		t.Fatal(err)
	}
}

// the references the configuration would not resolve (spec 009): a source not configured, outside the
// allowlist, a typed value, a variable, a sealed secret; with resolve, one that does not read; never a value
func TestCheckRefs(t *testing.T) {
	st := memory.New()
	put(t, st, "fine", `{"key_id":"AKIA","secret":"ref+kv://duckdb/a"}`)
	put(t, st, "renamed", `{"secret":"ref+vault-us://secret/x#f"}`)
	put(t, st, "narrowed", `{"secret":{"type":"VARCHAR","value":"ref+kv://other/b"}}`)
	put(t, st, "missing", `{"secret":"ref+kv://duckdb/gone"}`)
	put(t, st, "old", `{"secret":"hunter2"}`)
	put(t, st.Variables(), "region", `{"value":"ref+nope://x"}`)
	r := material.New(kv{allow: "duckdb/", values: map[string]string{"duckdb/a": "s3cr3t"}})
	sealed := sealedStore{Store: st, name: "old"}

	var out bytes.Buffer
	n, checked, err := checkRefs(context.Background(), sealed, r, false, &out)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if n != 4 || checked != 6 || len(lines) != 4 {
		t.Fatalf("%d findings in %d entries:\n%s", n, checked, out.String())
	}
	for _, want := range []string{
		"secret\tnarrowed\tsecret\t", "secret\told\t-\tdoes not open", "secret\trenamed\tsecret\t",
		"variable\tregion\tvalue\t",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("no %q in:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "missing") || strings.Contains(out.String(), "fine") {
		t.Fatalf("an admitted reference reported without -resolve:\n%s", out.String())
	}
	if strings.Contains(out.String(), "vault-us://secret") || strings.Contains(out.String(), "nope://x") {
		t.Fatalf("a text that did not parse was printed:\n%s", out.String())
	}

	out.Reset()
	n, _, _ = checkRefs(context.Background(), sealed, r, true, &out)
	if n != 5 || !strings.Contains(out.String(), "secret\tmissing\tsecret\tref+kv://v/duckdb/gone: no such secret") {
		t.Fatalf("with resolve, %d:\n%s", n, out.String())
	}
	if strings.Contains(out.String(), "s3cr3t") || strings.Contains(out.String(), "hunter2") {
		t.Fatal("a value was printed")
	}

	// nothing to report
	clean := memory.New()
	put(t, clean, "fine", `{"secret":"ref+kv://duckdb/a"}`)
	if n, _, err := checkRefs(context.Background(), clean, r, true, &out); n != 0 || err != nil {
		t.Fatalf("%d %v", n, err)
	}
}

// the command over a SQLite store: a finding is errFindings (exit 3), none is nil; a missing database is an
// error, never an empty one made
func TestRefsCommand(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRESOR_TEST_KEK", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	path := filepath.Join(dir, "server.yaml")
	db := filepath.Join(dir, "t.db")
	doc := `listen: 127.0.0.1:8443
public_url: http://127.0.0.1:8443
state: {kind: sqlite, path: ` + db + `}
keys: {kind: local, key_env: TRESOR_TEST_KEK}
issuers: [{issuer: 'http://127.0.0.1:18080/realms/t', audience: duckdb-secrets}]
policy: {admins: [role:secrets_admin]}
`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := refs(path, false, io.Discard, log); err == nil || !strings.Contains(err.Error(), "state.path") {
		t.Fatalf("a missing database: %v", err)
	}
	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// the service, serving: it holds the SQLite lease all along - refs reads beside it, leased by none
	st, _, err := openState(ctx, cfg, log, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	put(t, st, "lake", `{"secret":"ref+vault://secret/x#f"}`)
	var out bytes.Buffer
	if err := refs(path, false, &out, log); !errors.Is(err, errFindings) || !strings.Contains(out.String(), "secret\tlake\tsecret\t") {
		t.Fatalf("%v:\n%s", err, out.String())
	}
	if _, err := st.Update(ctx, "lake", func(*state.Secret) (*state.Secret, error) { return nil, nil }); err != nil {
		t.Fatalf("the service, after refs: %v", err)
	}
	if err := refs(path, false, io.Discard, log); err != nil {
		t.Fatalf("nothing to report: %v", err)
	}
	// a database no service has migrated: refused, not migrated
	empty := filepath.Join(dir, "empty.db")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(doc, db, empty, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := refs(path, false, io.Discard, log); err == nil || !strings.Contains(err.Error(), "migrations") {
		t.Fatalf("an empty database: %v", err)
	}
	if info, _ := os.Stat(empty); info.Size() != 0 {
		t.Fatal("refs wrote to the database")
	}
}

// failing is a store whose reads fail as an outage, or stop
type failing struct {
	state.Store
	err error
}

func (f failing) Get(context.Context, string) (*state.Secret, error) { return nil, f.err }

// an outage is an error, not findings; a stop is the context's error
func TestCheckRefsErrors(t *testing.T) {
	st := memory.New()
	put(t, st, "a", `{"secret":"ref+kv://duckdb/a"}`)
	put(t, st, "b", `{"secret":"ref+kv://duckdb/b"}`)
	r := material.New(kv{allow: "duckdb/"})
	var out bytes.Buffer
	n, _, err := checkRefs(context.Background(), failing{st, errors.New("unwrapping under the KEK: 403")}, r, false, &out)
	if err == nil || n != 0 || out.Len() != 0 {
		t.Fatalf("an outage: %d %v\n%s", n, err, out.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := checkRefs(ctx, failing{st, ctx.Err()}, r, false, &out); !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatalf("a stop: %v\n%s", err, out.String())
	}
}

// the command line: the command first, its own flags only, nothing after
func TestParseArgs(t *testing.T) {
	for line, want := range map[string]invocation{
		"-config x":                        {command: "serve", configPath: "x"},
		"refs -config x":                   {command: "refs", configPath: "x"},
		"refs -config x -resolve":          {command: "refs", configPath: "x", resolve: true},
		"rewrap -tag-untagged -config x":   {command: "rewrap", configPath: "x", tagUntagged: true},
		"mac -config x":                    {command: "mac", configPath: "x"},
		"reseal -config x":                 {command: "reseal", configPath: "x"},
		"reseal -rotate -retire -config x": {command: "reseal", configPath: "x", rotate: true, retire: true},
	} {
		if got, err := parseArgs(strings.Fields(line)); err != nil || got != want {
			t.Errorf("%s: %+v %v", line, got, err)
		}
	}
	for _, line := range []string{"-config x refs", "-config x rewrap", "refs -config x extra", "-resolve -config x",
		"rewrap -resolve", "refs -tag-untagged", "reseal -tag-untagged", "rewrap -retire", "-config x reseal"} {
		if _, err := parseArgs(strings.Fields(line)); err == nil {
			t.Errorf("%s: accepted", line)
		}
	}
}

// every command line the docs show is one the command line accepts (spec 019: the runbooks)
func TestDocsCommandLines(t *testing.T) {
	line := regexp.MustCompile("tresor-server ((?:rewrap|refs|mac|reseal)(?: +-[^\\s`|#]+(?: +[^\\s`|#-][^\\s`|#]*)?)*)")
	n := 0
	err := filepath.WalkDir("../../website/docs", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".md") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range line.FindAllStringSubmatch(string(data), -1) {
			n++
			if _, err := parseArgs(strings.Fields(m[1])); err != nil {
				t.Errorf("%s: tresor-server %s: %v", path, m[1], err)
			}
		}
		return nil
	})
	if err != nil || n < 10 {
		t.Fatalf("the docs' command lines: %d found, %v", n, err)
	}
}
