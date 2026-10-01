package api

import (
	"strings"
	"testing"

	azkv "github.com/hugr-lab/tresor-server/internal/material/azurekeyvault"
)

// variables (spec 004, tresor spec 018): the secrets' rules in a namespace of their own
func TestVariables(t *testing.T) {
	f := newFixture(t, "")
	if caps := f.do("GET", "/.well-known/duckdb-secrets", "", "").json(t)["capabilities"].(map[string]any); caps["variables"] != true {
		t.Fatalf("capabilities: %v", caps)
	}
	// only an administrator creates
	if r := f.do("PUT", "/v1/variables/lake_bucket", f.alice, `{"value":"s3://lake"}`); r.status != 403 {
		t.Fatalf("a user creating: %d %s", r.status, r.body)
	}
	r := f.do("PUT", "/v1/variables/lake_bucket", f.admin, `{"value":"s3://lake","comment":"the lake"}`)
	if r.status != 201 || r.header.Get("ETag") != `"1"` {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	d := r.json(t)
	if d["name"] != "lake_bucket" || d["comment"] != "the lake" || d["sensitive"] != false || d["version"] != "1" {
		t.Fatalf("the descriptor: %v", d)
	}
	if _, ok := d["value"]; ok {
		t.Fatal("a write's answer holds the value")
	}
	// invisible: 404; seen without use: 403
	if r := f.do("GET", "/v1/variables/lake_bucket", f.alice, ""); r.status != 404 || r.problemType(t) != "not_found" {
		t.Fatalf("invisible: %d %s", r.status, r.body)
	}
	if r := f.do("GET", "/v1/variables/lake_bucket", f.admin, ""); r.status != 403 {
		t.Fatalf("an admin with no use: %d %s", r.status, r.body)
	}
	if r := f.do("PUT", "/v1/variables/lake_bucket/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`); r.status != 200 {
		t.Fatalf("grant: %d %s", r.status, r.body)
	}
	r = f.do("GET", "/v1/variables/lake_bucket", f.alice, "")
	if r.status != 200 || r.json(t)["value"] != "s3://lake" || r.header.Get("Cache-Control") != "no-store" ||
		r.header.Get("ETag") != `"2"` {
		t.Fatalf("read: %d %s %v", r.status, r.body, r.header)
	}
	// a list carries no value
	list := f.do("GET", "/v1/variables", f.alice, "")
	if list.status != 200 || strings.Contains(string(list.body), "s3://lake") || !strings.Contains(string(list.body), "lake_bucket") {
		t.Fatalf("list: %d %s", list.status, list.body)
	}
	// conditional writes
	if r := f.do("PUT", "/v1/variables/lake_bucket", f.admin, `{"value":"x"}`, "If-None-Match", "*"); r.status != 412 {
		t.Fatalf("create over an existing one: %d", r.status)
	}
	if r := f.do("PUT", "/v1/variables/lake_bucket", f.admin, `{"value":"x"}`, "If-Match", `"1"`); r.status != 412 {
		t.Fatalf("a stale If-Match: %d", r.status)
	}
	if r := f.do("PUT", "/v1/variables/lake_bucket", f.admin, `{"value":"s3://lake2"}`, "If-Match", `"2"`); r.status != 200 {
		t.Fatalf("a replace: %d %s", r.status, r.body)
	}
	if r := f.do("GET", "/v1/variables/lake_bucket", f.alice, ""); r.json(t)["value"] != "s3://lake2" || r.json(t)["comment"] != "the lake" {
		t.Fatalf("after the replace (the comment kept): %s", r.body)
	}
	if r := f.do("PATCH", "/v1/variables/lake_bucket", f.admin, `{"comment":"renamed"}`); r.status != 200 || r.json(t)["comment"] != "renamed" {
		t.Fatalf("annotate: %d %s", r.status, r.body)
	}
	// the value: a JSON string, UTF-8, at most 64 KiB
	for what, body := range map[string]string{
		"no value":     `{"comment":"x"}`,
		"not a string": `{"value":42}`,
		"over 64 KiB":  `{"value":"` + strings.Repeat("x", 64<<10+1) + `"}`,
	} {
		if r := f.do("PUT", "/v1/variables/v2", f.admin, body); r.status != 422 {
			t.Errorf("%s: %d", what, r.status)
		}
	}
	if r := f.do("PUT", "/v1/variables/v64", f.admin, `{"value":"`+strings.Repeat("x", 64<<10)+`"}`); r.status != 201 {
		t.Fatalf("64 KiB is always accepted: %d", r.status)
	}
	if r := f.do("DELETE", "/v1/variables/lake_bucket", f.admin, ""); r.status != 204 {
		t.Fatalf("delete: %d %s", r.status, r.body)
	}
	if r := f.do("GET", "/v1/variables/lake_bucket", f.alice, ""); r.status != 404 {
		t.Fatalf("after delete: %d", r.status)
	}
}

// one name in both namespaces is two entries; a secret named like a variables path stays a secret
func TestVariablesNamespace(t *testing.T) {
	f := newFixture(t, "")
	f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret)
	if r := f.do("PUT", "/v1/variables/lake", f.admin, `{"value":"v"}`, "If-None-Match", "*"); r.status != 201 {
		t.Fatalf("a variable beside a secret of the name: %d %s", r.status, r.body)
	}
	if r := f.do("DELETE", "/v1/variables/lake", f.admin, ""); r.status != 204 {
		t.Fatal(r.status)
	}
	if r := f.do("GET", "/v1/secrets/lake/grants", f.admin, ""); r.status != 200 {
		t.Fatalf("the secret after the variable's delete: %d", r.status)
	}
	if r := f.do("PUT", "/v1/secrets/a%2Fv1%2Fvariables", f.admin, s3Secret); r.status != 201 {
		t.Fatalf("a secret named a/v1/variables: %d %s", r.status, r.body)
	}
	if r := f.do("GET", "/v1/variables", f.admin, ""); strings.TrimSpace(string(r.body)) != "[]" {
		t.Fatalf("it shows among the variables: %s", r.body)
	}
	if r := f.do("GET", "/v1/variables/nope", f.admin, ""); !strings.Contains(string(r.body), `no variable \"nope\"`) {
		t.Fatalf("not_found names a variable: %s", r.body)
	}
}

// a value that is a reference: written by an administrator within the allowlist, resolved at each read,
// sensitive; one that does not resolve fails the read - 503 may resolve later, 500 will not
func TestVariableReference(t *testing.T) {
	f := newFixture(t, "")
	v := &kvSecrets{values: map[string]string{"lake-conn": "Server=x;Password=hunter2"}}
	withVault(f, v, azkv.Allow{Vault: "corp-vault", Prefixes: []string{"lake-"}})
	if r := f.do("PUT", "/v1/variables/conn", f.admin, `{"value":"ref+azkv://corp-vault/other"}`); r.status != 422 {
		t.Fatalf("outside the allowlist: %d", r.status)
	}
	r := f.do("PUT", "/v1/variables/conn", f.admin, `{"value":"ref+azkv://corp-vault/lake-conn"}`)
	if r.status != 201 || r.json(t)["sensitive"] != true {
		t.Fatalf("a reference: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/variables/conn/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	r = f.do("GET", "/v1/variables/conn", f.alice, "")
	if r.status != 200 || r.json(t)["value"] != "Server=x;Password=hunter2" || r.json(t)["sensitive"] != true {
		t.Fatalf("resolved: %d %s", r.status, r.body)
	}
	if l := f.do("GET", "/v1/variables", f.alice, ""); !strings.Contains(string(l.body), `"sensitive":true`) {
		t.Fatalf("listed as sensitive: %s", l.body)
	}
	if strings.Contains(f.logs.String(), "hunter2") {
		t.Fatal("a resolved value reached the log")
	}
	v.down.Store(true)
	if r := f.do("GET", "/v1/variables/conn", f.alice, ""); r.status != 503 {
		t.Fatalf("the vault down: %d", r.status)
	}
	v.down.Store(false)
	withVault(f, v, azkv.Allow{Vault: "corp-vault", Prefixes: []string{"duckdb-"}})
	if r := f.do("GET", "/v1/variables/conn", f.alice, ""); r.status != 500 || r.problemType(t) != "service_error" {
		t.Fatalf("outside the allowlist now: %d %s", r.status, r.body)
	}
	// a plain value replacing it is not sensitive
	if r := f.do("PUT", "/v1/variables/conn", f.admin, `{"value":"plain"}`); r.json(t)["sensitive"] != false {
		t.Fatalf("a plain value: %s", r.body)
	}
}
