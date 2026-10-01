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
		"a vault key with no identity": strings.Replace(withKeys, "keys: {kind: local, key_env: TRESOR_TEST_KEK,",
			"keys: {kind: azurekeyvault, key: 'https://kv.vault.azure.net/keys/k',", 1),
		"a vault key and a key_env": strings.Replace(withKeys, "keys: {kind: local,", "azure: {identity: default}\nkeys: {kind: azurekeyvault, key: 'https://kv.vault.azure.net/keys/k',", 1),
		"a vault key over http": strings.Replace(withKeys, "keys: {kind: local, key_env: TRESOR_TEST_KEK,",
			"azure: {identity: default}\nkeys: {kind: azurekeyvault, key: 'http://kv/keys/k',", 1),
		"a client id for the default credential": strings.Replace(withKeys, "keys: {kind: local, key_env: TRESOR_TEST_KEK,",
			"azure: {identity: default, client_id: x}\nkeys: {kind: azurekeyvault, key: 'https://kv.vault.azure.net/keys/k',", 1),
		"an unknown identity": withKeys + "azure: {identity: secret}\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKeyVaultConfig(t *testing.T) {
	doc := strings.Replace(good, "state: {kind: memory}", "state: {kind: sqlite, path: /data/t.db}", 1) +
		"keys: {kind: azurekeyvault, key: 'https://corp-kv.vault.azure.net/keys/tresor-kek'}\n" +
		"azure: {identity: managed, client_id: 00000000-0000-0000-0000-000000000001}\n"
	cfg, err := Parse([]byte(doc))
	if err != nil || cfg.Keys.Key != "https://corp-kv.vault.azure.net/keys/tresor-kek" || cfg.Azure.Identity != "managed" {
		t.Fatalf("%v %+v", err, cfg)
	}
}

func TestDatabaseServer(t *testing.T) {
	base := strings.Replace(good, "state: {kind: memory}", "state: {kind: postgres, dsn: 'host=db user=tresor dbname=tresor', auth: password, password_env: TRESOR_TEST_DB_PW}", 1) +
		"keys: {kind: local, key_env: TRESOR_TEST_KEK}\n"
	if _, err := Parse([]byte(base)); err != nil {
		t.Fatal(err)
	}
	entra := strings.Replace(base, "auth: password, password_env: TRESOR_TEST_DB_PW", "auth: entra", 1) + "azure: {identity: managed}\n"
	if _, err := Parse([]byte(entra)); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(strings.Replace(base, "password_env: TRESOR_TEST_DB_PW", "password_ref: 'ref+k8s://db/pg/password'", 1) +
		"material: {k8s: {allow: [{namespace: db, prefixes: [duckdb-]}, {namespace: data}]}}\n")); err != nil {
		t.Fatalf("a password from a Kubernetes Secret, outside the allowlist: %v", err)
	}
	for name, doc := range map[string]string{
		"no dsn":                  strings.Replace(base, "dsn: 'host=db user=tresor dbname=tresor', ", "", 1),
		"a password in the dsn":   strings.Replace(base, "dbname=tresor'", "dbname=tresor password=x'", 1),
		"no auth":                 strings.Replace(base, "auth: password, password_env: TRESOR_TEST_DB_PW", "", 1),
		"entra with no identity":  strings.Replace(base, "auth: password, password_env: TRESOR_TEST_DB_PW", "auth: entra", 1),
		"a password from nowhere": strings.Replace(base, ", password_env: TRESOR_TEST_DB_PW", "", 1),
		"a password in a setting's variable": strings.Replace(base, "password_env: TRESOR_TEST_DB_PW",
			"password_env: TRESOR_LISTEN", 1),
		"a dsn for sqlite": strings.Replace(good, "state: {kind: memory}", "state: {kind: sqlite, path: /t.db, dsn: x}", 1) +
			"keys: {kind: local, key_env: TRESOR_TEST_KEK}\n",
		"no KEK": strings.Replace(base, "keys: {kind: local, key_env: TRESOR_TEST_KEK}\n", "", 1),
		"a password from two places": strings.Replace(base, "password_env: TRESOR_TEST_DB_PW",
			"password_env: TRESOR_TEST_DB_PW, password_ref: 'ref+k8s://db/pg/password'", 1),
		"a password_ref not a reference": strings.Replace(base, "password_env: TRESOR_TEST_DB_PW", "password_ref: hunter2", 1),
		"a password_ref of Key Vault with no identity": strings.Replace(base, "password_env: TRESOR_TEST_DB_PW",
			"password_ref: 'ref+azkv://kv/pg-password'", 1),
		"a password_ref an administrator could read": strings.Replace(base, "password_env: TRESOR_TEST_DB_PW",
			"password_ref: 'ref+k8s://db/duckdb-pg/password'", 1) + "material: {k8s: {allow: [{namespace: db, prefixes: [duckdb-]}]}}\n",
		"a password_ref in an allowed vault": strings.Replace(base, "password_env: TRESOR_TEST_DB_PW",
			"password_ref: 'ref+azkv://KV1/PG-password'", 1) + "azure: {identity: managed}\nmaterial: {azkv: {allow: [{vault: kv1}]}}\n",
		"entra and a password_ref": strings.Replace(entra, "auth: entra", "auth: entra, password_ref: 'ref+k8s://db/pg/password'", 1),
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDSNHasPassword(t *testing.T) {
	for dsn, want := range map[string]bool{
		"postgres://u:secret@h/db":                      true,
		"postgres://u@h/db?password=secret":             true,
		"host=h user=u password=secret dbname=db":       true,
		"host=h user=u password = secret":               true,
		"sqlserver://h?database=db;Pwd=x":               true,
		"postgres://u@h/passwords_db?sslmode=disable":   false,
		"host=h user=password_reader dbname=passwords":  false,
		"host=h user=u dbname=db sslmode=verify-full":   false,
		"sqlserver://h?database=password_vault&fedauth": false,
	} {
		if got := DSNHasPassword(dsn); got != want {
			t.Errorf("%s: %v", dsn, got)
		}
	}
}

func TestMaterialConfig(t *testing.T) {
	base := good + "azure: {identity: default}\nmaterial: {azkv: {allow: [{vault: corp-vault, prefixes: [lake-]}]}}\n"
	if _, err := Parse([]byte(base)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"a suffix to another host": strings.Replace(base, "allow:", "dns_suffix: '.vault.azure.net@evil.example', allow:", 1),
		"a suffix with no dot":     strings.Replace(base, "allow:", "dns_suffix: vault.azure.net, allow:", 1),
		"a cache over 5 minutes":   strings.Replace(base, "allow:", "cache_ttl: 10m, allow:", 1),
		"a vault's name":           strings.Replace(base, "vault: corp-vault", "vault: corp.vault.azure.net", 1),
		"no identity":              strings.Replace(base, "azure: {identity: default}\n", "", 1),
		"no vault listed":          strings.Replace(base, "allow: [{vault: corp-vault, prefixes: [lake-]}]", "cache_ttl: 1m", 1),
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte(strings.Replace(base, "allow:", "dns_suffix: .vault.usgovcloudapi.net, cache_ttl: 5m, allow:", 1))); err != nil {
		t.Fatalf("a sovereign cloud's suffix, a 5-minute cache: %v", err)
	}
}

// TLS ending at the platform's ingress (Container Apps): plain http on any address, public_url https
func TestTLSOffload(t *testing.T) {
	doc := strings.Replace(strings.Replace(good, "listen: 127.0.0.1:8443", "listen: 0.0.0.0:8080", 1),
		"public_url: http://127.0.0.1:8443", "public_url: https://secrets.corp.example", 1) + "tls: {offload: true}\n"
	if _, err := Parse([]byte(doc)); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"no offload":           strings.Replace(doc, "tls: {offload: true}\n", "", 1),
		"http behind it":       strings.Replace(doc, "https://secrets.corp.example", "http://secrets.corp.example", 1),
		"a cert and offloaded": strings.Replace(doc, "tls: {offload: true}", "tls: {offload: true, cert: c, key: k}", 1),
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKubernetesState(t *testing.T) {
	keys := "keys: {kind: local, key_file: /run/secrets/kek}\n"
	kube := strings.Replace(good, "state: {kind: memory}", "state: {kind: kubernetes, namespace: tresor, instance: prod}", 1) + keys
	cfg, err := Parse([]byte(kube))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.State.Namespace != "tresor" || cfg.State.Instance != "prod" {
		t.Fatalf("state: %+v", cfg.State)
	}
	if _, err := Parse([]byte(strings.Replace(kube, ", namespace: tresor, instance: prod", "", 1))); err != nil {
		t.Fatalf("in a pod, the namespace is the pod's: %v", err)
	}
	for name, doc := range map[string]string{
		"no keys":               strings.Replace(kube, keys, "", 1),
		"a namespace no label":  strings.Replace(kube, "namespace: tresor", "namespace: Tresor_1", 1),
		"a namespace on sqlite": strings.Replace(good, "state: {kind: memory}", "state: {kind: sqlite, path: /d, namespace: x}", 1) + keys,
		"a dsn":                 strings.Replace(kube, "instance: prod", "dsn: 'postgres://u@h/d'", 1),
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMaterialK8s(t *testing.T) {
	doc := good + "material: {k8s: {allow: [{namespace: data-team, prefixes: [duckdb-]}, {namespace: open}]}}\n"
	cfg, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if a := cfg.Material.K8s.Allow; len(a) != 2 || a[0].Namespace != "data-team" || a[0].Prefixes[0] != "duckdb-" {
		t.Fatalf("material.k8s: %+v", cfg.Material.K8s)
	}
	if _, err := Parse([]byte(strings.Replace(doc, "namespace: data-team", "namespace: Data_Team", 1))); err == nil {
		t.Fatal("a namespace that is no DNS label")
	}
}

func TestWorkloadIdentity(t *testing.T) {
	doc := strings.Replace(good, "state: {kind: memory}", "state: {kind: kubernetes}", 1) +
		"keys: {kind: azurekeyvault, key: 'https://kv.vault.azure.net/keys/k'}\nazure: {identity: workload}\n"
	if _, err := Parse([]byte(doc)); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(strings.Replace(doc, "identity: workload", "identity: workload, client_id: x", 1))); err != nil {
		t.Fatalf("workload with a client id: %v", err)
	}
}
