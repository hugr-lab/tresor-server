package vaultkv

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hugr-lab/tresor-server/internal/material"
	"github.com/hugr-lab/tresor-server/internal/vault"
	"github.com/hugr-lab/tresor-server/internal/vault/vaulttest"
)

var ctx = context.Background()

func TestParse(t *testing.T) {
	s := New(nil, []Allow{{Mount: "secret", Prefixes: []string{"duckdb/"}}, {Mount: "open"}}, 0)
	for text, want := range map[string]string{
		"secret/duckdb/lake#secret":       "ref+vault://secret/duckdb/lake#secret",
		"secret/duckdb/a/b.c/d-e#AWS_KEY": "ref+vault://secret/duckdb/a/b.c/d-e#AWS_KEY",
		"open/anything#f":                 "ref+vault://open/anything#f",
	} {
		ref, err := s.Parse(text)
		if err != nil || ref.String() != want {
			t.Errorf("%s: %v %v", text, ref, err)
		}
	}
	for _, text := range []string{
		"secret/duckdb/lake",          // no field
		"secret#f",                    // no path
		"secret/duckdb/../x#f",        // a .. segment
		"secret/duckdb/./x#f",         // a . segment
		"secret/duckdb/a%2Fb#f",       // an escape
		"secret/duckdb/x?version=1#f", // a query
		"secret/other/x#f",            // outside the prefixes
		"kv/duckdb/x#f",               // outside the mounts
		"secret/duckdb/x#f#g",         // two fields
		"secret//duckdb#f",            // an empty segment
		"../secret/duckdb/x#f",        // a mount ..
	} {
		if _, err := s.Parse(text); err == nil {
			t.Errorf("%s: accepted", text)
		}
	}
}

// against each server given: a field read, its version, a new version seen at the next read, a delete, a
// field that is not text, the allowlist again at the read
func TestKV(t *testing.T) {
	for _, srv := range vaulttest.Servers(t) {
		t.Run(srv.Name, func(t *testing.T) {
			mount := srv.Mount(t, "kv-v2")
			srv.Call(t, "POST", mount+"/data/duckdb/lake", map[string]any{"data": map[string]any{"secret": "s3cr3t-1", "n": 7}}, nil)
			client, _ := vault.New(vault.Config{Address: srv.Address, Auth: vault.Auth{Method: "token_file", TokenFile: srv.TokenFile(t)}})
			src := New(client, []Allow{{Mount: mount, Prefixes: []string{"duckdb/"}}}, 0)
			r := material.New(src)
			params := map[string]json.RawMessage{"secret": json.RawMessage(`"ref+vault://` + mount + `/duckdb/lake#secret"`)}
			out, done, err := r.Resolve(ctx, params)
			if err != nil || string(out["secret"]) != `"s3cr3t-1"` || len(done) != 1 || done[0].Version != "1" {
				t.Fatalf("resolved %s %+v %v", out["secret"], done, err)
			}
			srv.Call(t, "POST", mount+"/data/duckdb/lake", map[string]any{"data": map[string]any{"secret": "s3cr3t-2"}}, nil)
			if out, done, _ := r.Resolve(ctx, params); string(out["secret"]) != `"s3cr3t-2"` || done[0].Version != "2" {
				t.Fatalf("a new version: %s", out["secret"])
			}
			ref, _ := src.Parse(mount + "/duckdb/lake#n")
			srv.Call(t, "POST", mount+"/data/duckdb/lake", map[string]any{"data": map[string]any{"n": 7}}, nil)
			if _, _, err := src.Resolve(ctx, ref); err == nil {
				t.Fatal("a field that is not text")
			}
			srv.Call(t, "DELETE", mount+"/data/duckdb/lake", nil, nil)
			if _, _, err := r.Resolve(ctx, params); !errors.Is(err, material.ErrUnresolved) || strings.Contains(err.Error(), "s3cr3t") {
				t.Fatalf("a deleted secret: %v", err)
			}
			narrowed := material.New(New(client, []Allow{{Mount: mount, Prefixes: []string{"other/"}}}, 0))
			if _, _, err := narrowed.Resolve(ctx, params); !errors.Is(err, material.ErrInvalid) {
				t.Fatalf("outside the allowlist now: %v", err)
			}
		})
	}
}

// counting is a Vault that counts reads and answers one KV secret
type counting struct{ reads int }

func (c *counting) Do(_ context.Context, _, path string, _, out any) error {
	c.reads++
	raw := `{"data":{"data":{"secret":"v"},"metadata":{"version":3}}}`
	if strings.Contains(path, "/data/kv1") {
		raw = `{"data":{"data":{"secret":"v"}}}` // a KV v1 mount: no metadata
	}
	return json.Unmarshal([]byte(raw), out)
}

// the cache serves within its time, after the allowlist; a prefix is a plain start; a mount not KV v2 is
// refused at the read
func TestCache(t *testing.T) {
	v := &counting{}
	s := New(v, []Allow{{Mount: "secret", Prefixes: []string{"duckdb"}}}, time.Minute)
	ref, _ := s.Parse("secret/duckdb/lake#secret")
	for range 3 {
		if val, ver, err := s.Resolve(ctx, ref); err != nil || val != "v" || ver != "3" {
			t.Fatalf("%q %q %v", val, ver, err)
		}
	}
	if v.reads != 1 {
		t.Fatalf("%d reads within the cache's time", v.reads)
	}
	if _, err := s.Parse("secret/duckdb2/x#secret"); err != nil {
		t.Fatalf("a plain prefix admits duckdb2/: %v (end prefixes with /)", err)
	}
	s.allow = []Allow{{Mount: "secret", Prefixes: []string{"other/"}}}
	if _, _, err := s.Resolve(ctx, ref); err == nil {
		t.Fatal("a cached value outside the allowlist now")
	}
	kv1 := New(&counting{}, []Allow{{Mount: "secret"}}, 0)
	ref1, _ := kv1.Parse("secret/kv1#secret")
	if _, _, err := kv1.Resolve(ctx, ref1); err == nil || !strings.Contains(err.Error(), "KV v2") {
		t.Fatalf("a KV v1 mount: %v", err)
	}
}
