package config

import (
	"strings"
	"testing"
	"time"
)

const good = `
listen: 127.0.0.1:8443
public_url: http://127.0.0.1:8443
state: {kind: memory}
issuers:
  - issuer: http://127.0.0.1:18080/realms/tresor/
    audience: duckdb-secrets
policy:
  admins: [role:secrets_admin]
  actors:
    - {principal: client:node, verbs: [use]}
`

func TestGood(t *testing.T) {
	cfg, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuers[0].Issuer != "http://127.0.0.1:18080/realms/tresor/" || IssuerKey(cfg.Issuers[0].Issuer) != "http://127.0.0.1:18080/realms/tresor" {
		t.Fatal("the issuer is kept verbatim (RFC 8414 compares exactly); only its lookup key is normalised")
	}
	if len(cfg.Issuers[0].Algorithms) != 2 {
		t.Fatal("algorithms default to RS256, ES256")
	}
}

func TestRefused(t *testing.T) {
	cases := map[string]string{
		"plain http off loopback": strings.Replace(good, "listen: 127.0.0.1:8443", "listen: 0.0.0.0:8443", 1),
		"public http off loopback": strings.Replace(good, "public_url: http://127.0.0.1:8443",
			"public_url: http://secrets.corp", 1),
		"an unknown key": good + "\nextra: 1\n",
		"a symmetric algorithm": strings.Replace(good, "audience: duckdb-secrets",
			"audience: duckdb-secrets\n    algorithms: [HS256]", 1),
		"no audience":                  strings.Replace(good, "    audience: duckdb-secrets\n", "", 1),
		"a bad principal":              strings.Replace(good, "role:secrets_admin", "secrets_admin", 1),
		"the reference server's store": good + "store: {path: x.enc}\n",
		"an empty store":               good + "store:\n",
		"no state":                     strings.Replace(good, "state: {kind: memory}\n", "", 1),
		"an unknown state kind":        strings.Replace(good, "kind: memory", "kind: etcd", 1),
		"an actor with no verbs":       strings.Replace(good, "verbs: [use]", "verbs: []", 1),
		"an actor's unknown verb":      strings.Replace(good, "verbs: [use]", "verbs: [use, fly]", 1),
		"the old create policy":        good + "  create:\n    - {principal: role:analysts, names: [\"*\"]}\n",
		"no issuers":                   "listen: 127.0.0.1:1\npublic_url: http://127.0.0.1:1\nstate: {kind: memory}\n",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCreateGone(t *testing.T) {
	_, err := Parse([]byte(good + "  create:\n    - {principal: role:analysts, names: [\"*\"]}\n"))
	if err == nil || !strings.Contains(err.Error(), "policy.create is gone") {
		t.Fatalf("a config with policy.create: %v", err)
	}
}

func TestExchangeClient(t *testing.T) {
	with := strings.Replace(good, "audience: duckdb-secrets",
		"audience: duckdb-secrets\n    exchange: {client_id: duckdb-secrets, client_secret_env: TRESOR_TEST_EX}", 1)
	t.Setenv("TRESOR_TEST_EX", "")
	if _, err := Parse([]byte(with)); err == nil || !strings.Contains(err.Error(), "TRESOR_TEST_EX is empty") {
		t.Fatalf("an empty secret env: %v", err)
	}
	t.Setenv("TRESOR_TEST_EX", "s3cr3t")
	cfg, err := Parse([]byte(with))
	if err != nil || cfg.Issuers[0].Exchange.ClientSecret != "s3cr3t" {
		t.Fatalf("the secret from the env: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(with, "client_id: duckdb-secrets, ", "", 1))); err == nil {
		t.Fatal("an exchange without client_id")
	}
	if _, err := Parse([]byte(strings.Replace(with, "client_secret_env: TRESOR_TEST_EX", "client_secret: x", 1))); err == nil {
		t.Fatal("a client secret in the file")
	}
}

// a store on disk needs a KEK: material is sealed at rest (spec 002)
func TestStateAndKeys(t *testing.T) {
	sqlite := strings.Replace(good, "state: {kind: memory}", "state: {kind: sqlite, path: /data/tresor.db}", 1)
	withKeys := sqlite + "keys: {kind: local, key_env: TRESOR_TEST_KEK, data_key_max_age: 720h, cache_ttl: 1m}\n"
	cfg, err := Parse([]byte(withKeys))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Keys.DataKeyMaxAge != 720*time.Hour || cfg.Keys.CacheTTL != time.Minute {
		t.Fatalf("durations: %+v", cfg.Keys)
	}
	for name, doc := range map[string]string{
		"sqlite without keys":     sqlite,
		"sqlite without a path":   strings.Replace(withKeys, ", path: /data/tresor.db", "", 1),
		"a key from env and file": strings.Replace(withKeys, "key_env: TRESOR_TEST_KEK", "key_env: A, key_file: /k", 1),
		"no key source":           strings.Replace(withKeys, "key_env: TRESOR_TEST_KEK, ", "", 1),
		"an unknown key kind":     strings.Replace(withKeys, "kind: local", "kind: hsm", 1),
		"a KEK in a setting's variable": strings.Replace(withKeys, "key_env: TRESOR_TEST_KEK",
			"key_env: TRESOR_LISTEN", 1),
		"a negative duration": strings.Replace(withKeys, "cache_ttl: 1m", "cache_ttl: -1m", 1),
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
