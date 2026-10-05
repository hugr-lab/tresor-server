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

func TestExchangeClientAuth(t *testing.T) {
	issuer := func(exchange string) string {
		return strings.Replace(good, "audience: duckdb-secrets\n", "audience: duckdb-secrets\n    exchange: "+exchange+"\n", 1)
	}
	bao := "vault: {address: 'https://bao.example:8200', auth: {method: kubernetes, role: tresor}}\n"
	for name, doc := range map[string]string{
		"azure (managed)":    issuer("{client_id: app, client_auth: azure}") + "azure: {identity: managed}\n",
		"file":               issuer("{client_id: app, client_auth: file, assertion_file: /var/run/secrets/tokens/idp}"),
		"key_file (ZITADEL)": issuer("{client_auth: key_file, key_file: /etc/tresor/zitadel.json}"),
		"key_file, PEM":      issuer("{client_id: app, client_auth: key_file, key_file: /k.pem, kid: k1, assertion_audience: token_endpoint}"),
		"keyvault":           issuer("{client_id: app, client_auth: keyvault, key: 'https://kv.vault.azure.net/keys/sign', kid: x5t}") + "azure: {identity: workload}\n",
		"vault":              issuer("{client_id: app, client_auth: vault, key: transit/zitadel, kid: '2861'}") + bao,
	} {
		if _, err := Parse([]byte(doc)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, doc := range map[string]string{
		"an unknown kind":              issuer("{client_id: app, client_auth: magic}"),
		"azure with no identity":       issuer("{client_id: app, client_auth: azure}"),
		"azure with default":           issuer("{client_id: app, client_auth: azure}") + "azure: {identity: default}\n",
		"file with no file":            issuer("{client_id: app, client_auth: file}"),
		"a secret beside an assertion": issuer("{client_id: app, client_auth: file, assertion_file: /t, client_secret_env: X}"),
		"keyvault with no kid":         issuer("{client_id: app, client_auth: keyvault, key: 'https://kv.vault.azure.net/keys/sign'}") + "azure: {identity: managed}\n",
		"a key for key_file":           issuer("{client_id: app, client_auth: key_file, key_file: /k, key: 'https://kv/keys/x'}"),
		"an odd audience":              issuer("{client_id: app, client_auth: key_file, key_file: /k, assertion_audience: everyone}"),
		"secret with no variable":      issuer("{client_id: app}"),
		"no client_id for file":        issuer("{client_auth: file, assertion_file: /t}"),
		"vault with no vault":          issuer("{client_id: app, client_auth: vault, key: transit/zitadel, kid: k}"),
		"vault with no kid":            issuer("{client_id: app, client_auth: vault, key: transit/zitadel}") + bao,
		"vault with no mount":          issuer("{client_id: app, client_auth: vault, key: zitadel, kid: k}") + bao,
		"vault with a dot key":         issuer("{client_id: app, client_auth: vault, key: transit/.., kid: k}") + bao,
		"vault with a nested mount":    issuer("{client_id: app, client_auth: vault, key: team/transit/k, kid: k}") + bao,
		"vault with a deep key":        issuer("{client_id: app, client_auth: vault, key: transit/a/b, kid: k}") + bao,
		"vault with a key_file":        issuer("{client_id: app, client_auth: vault, key: transit/z, kid: k, key_file: /k}") + bao,
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVaultConfig(t *testing.T) {
	base := strings.Replace(good, "state: {kind: memory}", "state: {kind: sqlite, path: /d/t.db}", 1)
	vaultKEK := base + "keys: {kind: vault, key: tresor-kek}\nvault: {address: 'https://bao.example:8200', auth: {method: kubernetes, role: tresor}}\n"
	cfg, err := Parse([]byte(vaultKEK))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Keys.Mount != "transit" || cfg.Vault.Auth.Role != "tresor" {
		t.Fatalf("%+v %+v", cfg.Keys, cfg.Vault)
	}
	for name, doc := range map[string]string{
		"jwt":        strings.Replace(vaultKEK, "method: kubernetes, role: tresor", "method: jwt, role: tresor, jwt_file: /var/run/tresor/vault-token/token", 1),
		"token_file": strings.Replace(vaultKEK, "method: kubernetes, role: tresor", "method: token_file, token_file: /vault/secrets/token", 1),
	} {
		if _, err := Parse([]byte(doc)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, doc := range map[string]string{
		"a vault KEK with no vault":  base + "keys: {kind: vault, key: k}\n",
		"a key with a slash":         strings.Replace(vaultKEK, "key: tresor-kek", "key: transit/tresor-kek", 1),
		"jwt with no file":           strings.Replace(vaultKEK, "method: kubernetes", "method: jwt", 1),
		"approle":                    strings.Replace(vaultKEK, "method: kubernetes", "method: approle", 1),
		"token_file with a role":     strings.Replace(vaultKEK, "method: kubernetes, role: tresor", "method: token_file, token_file: /t, role: x", 1),
		"a mount for a local KEK":    base + "keys: {kind: local, key_env: TRESOR_TEST_KEK, mount: transit}\n",
		"vault settings, no address": base + "keys: {kind: local, key_env: TRESOR_TEST_KEK}\nvault: {namespace: x}\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMaterialVault(t *testing.T) {
	vaultCfg := "vault: {address: 'https://bao.example', auth: {method: kubernetes, role: tresor}}\n"
	doc := good + vaultCfg + "material: {vault: {allow: [{mount: secret, prefixes: [duckdb/]}], cache_ttl: 1m}}\n"
	if _, err := Parse([]byte(doc)); err != nil {
		t.Fatal(err)
	}
	pg := strings.Replace(good, "state: {kind: memory}", "state: {kind: postgres, dsn: 'host=db user=t dbname=t', auth: password, password_ref: 'ref+vault://secret/tresor/db#password'}", 1) +
		"keys: {kind: local, key_env: TRESOR_TEST_KEK}\n" + vaultCfg
	if _, err := Parse([]byte(pg + "material: {vault: {allow: [{mount: secret, prefixes: [duckdb/]}]}}\n")); err != nil {
		t.Fatalf("a password outside the allowlist: %v", err)
	}
	for name, d := range map[string]string{
		"no vault":              good + "material: {vault: {allow: [{mount: secret}]}}\n",
		"a nested mount":        good + vaultCfg + "material: {vault: {allow: [{mount: team/kv}]}}\n",
		"a long cache":          good + vaultCfg + "material: {vault: {allow: [{mount: secret}], cache_ttl: 1h}}\n",
		"the password readable": pg + "material: {vault: {allow: [{mount: secret, prefixes: [tresor/]}]}}\n",
		"a password, no vault":  strings.Replace(pg, vaultCfg, "", 1),
	} {
		if _, err := Parse([]byte(d)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// named sources (spec 008): a name of their own, a kind, a connection of their own or the top-level one, an
// allowlist; state.password_ref through one, outside its allowlist
func TestNamedSources(t *testing.T) {
	top := "vault: {address: 'https://bao.example', auth: {method: kubernetes, role: tresor}}\nazure: {identity: workload}\n"
	us := "{name: vault-us, kind: vault, vault: {address: 'https://bao.us.example', auth: {method: jwt, role: t, jwt_file: /t}}, allow: [{mount: secret, prefixes: [duckdb/]}], cache_ttl: 1m}"
	partner := "{name: partner, kind: azkv, azure: {identity: workload, client_id: app, tenant_id: other}, allow: [{vault: partner-kv, prefixes: [duckdb-]}]}"
	inherit := "{name: bao2, kind: vault, allow: [{mount: kv}]}"
	doc := good + top + "material:\n  vault: {allow: [{mount: secret}]}\n  sources: [" + us + ", " + partner + ", " + inherit + "]\n"
	cfg, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := cfg.Source("vault-us"); !ok || s.Vault.Address != "https://bao.us.example" || s.Kind != "vault" ||
		s.VaultAllow.CacheTTL != time.Minute || s.VaultAllow.Allow[0].Mount != "secret" {
		t.Fatalf("vault-us: %+v", s)
	}
	if s, _ := cfg.Source("bao2"); s.Vault != cfg.Vault {
		t.Fatal("a source with no vault: is not the top-level one's")
	}
	if s, _ := cfg.Source("partner"); s.Azure.TenantID != "other" || s.AzKV.Allow[0].Vault != "partner-kv" {
		t.Fatalf("partner: %+v", s)
	}
	if _, ok := cfg.Source("nope"); ok {
		t.Fatal("a name no source has")
	}
	var names []string
	for _, s := range cfg.Sources() {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != "vault,vault-us,partner,bao2" {
		t.Fatalf("sources: %v", names)
	}

	// a password through a named source: outside its allowlist, with its connection
	pg := strings.Replace(good, "state: {kind: memory}", "state: {kind: postgres, dsn: 'host=db user=t dbname=t', auth: password, password_ref: 'REF'}", 1) +
		"keys: {kind: local, key_env: TRESOR_TEST_KEK}\n" + top + "material: {sources: [" + us + "]}\n"
	if _, err := Parse([]byte(strings.Replace(pg, "REF", "ref+vault-us://secret/tresor/db#password", 1))); err != nil {
		t.Fatalf("a password outside a named source's allowlist: %v", err)
	}
	for name, ref := range map[string]string{
		"within its allowlist": "ref+vault-us://secret/duckdb/db#password",
		"a name no source has": "ref+nope://secret/tresor/db#password",
	} {
		if _, err := Parse([]byte(strings.Replace(pg, "REF", ref, 1))); err == nil {
			t.Errorf("a password %s: accepted", name)
		}
	}

	src := func(s string) string {
		return good + top + "material:\n  vault: {allow: [{mount: secret}]}\n  sources: [" + s + "]\n"
	}
	for name, d := range map[string]string{
		"a built-in section's name":       src("{name: vault, kind: vault, allow: [{mount: kv}]}"),
		"a name twice":                    src(inherit + ", " + inherit),
		"an upper-case name":              src("{name: Bao, kind: vault, allow: [{mount: kv}]}"),
		"a name from a digit":             src("{name: 2bao, kind: vault, allow: [{mount: kv}]}"),
		"a long name":                     src("{name: abcdefghijklmnopq, kind: vault, allow: [{mount: kv}]}"),
		"a k8s source":                    src("{name: other, kind: k8s, allow: [{mount: kv}]}"),
		"an unknown kind":                 src("{name: other, kind: aws, allow: [{mount: kv}]}"),
		"no allowlist":                    src("{name: bao2, kind: vault}"),
		"a vault entry in a vault source": src("{name: bao2, kind: vault, allow: [{vault: kv}]}"),
		"a mount in an azkv source":       src("{name: kv2, kind: azkv, allow: [{mount: kv}]}"),
		"azure in a vault source":         src("{name: bao2, kind: vault, azure: {identity: managed}, allow: [{mount: kv}]}"),
		"vault in an azkv source":         src("{name: kv2, kind: azkv, vault: {address: 'https://b'}, allow: [{vault: kv2}]}"),
		"its vault with no address":       src("{name: bao2, kind: vault, vault: {namespace: x}, allow: [{mount: kv}]}"),
		"its vault with no auth":          src("{name: bao2, kind: vault, vault: {address: 'https://b'}, allow: [{mount: kv}]}"),
		"sys":                             src("{name: bao2, kind: vault, allow: [{mount: sys}]}"),
		"a tenant with managed":           src("{name: kv2, kind: azkv, azure: {identity: managed, tenant_id: t}, allow: [{vault: kv2}]}"),
		"a long cache":                    src("{name: bao2, kind: vault, allow: [{mount: kv}], cache_ttl: 1h}"),
		"no top-level vault":              good + "material: {sources: [" + inherit + "]}\n",
		"no Azure identity":               good + "material: {sources: [{name: kv2, kind: azkv, allow: [{vault: kv2}]}]}\n",
		"a tenant at the top":             good + "azure: {identity: workload, tenant_id: t}\n",
	} {
		if _, err := Parse([]byte(d)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a kind's own name is never a named source's, configured or not: a password or a reference written to
	// it would move to another server
	for _, name := range []string{"vault", "k8s", "azkv", "aws", "gcp"} {
		if _, err := Parse([]byte(good + top + "material: {sources: [{name: " + name + ", kind: vault, allow: [{mount: kv}]}]}\n")); err == nil {
			t.Errorf("a source named %s: accepted", name)
		}
	}
}

// the database's password is outside every source of its kind (spec 008): another may admit the same place, on
// the same server or vault
func TestPasswordOutsideEverySource(t *testing.T) {
	top := "vault: {address: 'https://bao.example', auth: {method: kubernetes, role: tresor}}\nazure: {identity: workload}\n"
	pg := func(ref, material string) string {
		return strings.Replace(good, "state: {kind: memory}", "state: {kind: postgres, dsn: 'host=db user=t dbname=t', auth: password, password_ref: '"+ref+"'}", 1) +
			"keys: {kind: local, key_env: TRESOR_TEST_KEK}\n" + top + "material: " + material + "\n"
	}
	bao2 := "{name: bao2, kind: vault, allow: [{mount: kv}]}"
	own := func(name string) string {
		return "{name: " + name + ", kind: vault, vault: {address: 'https://bao.us.example', auth: {method: kubernetes, role: t}}, allow: [{mount: kv}]}"
	}
	for name, doc := range map[string]string{
		"through a named source, admitted by the built-in":           pg("ref+bao2://secret/tresor/db#password", "{vault: {allow: [{mount: secret}]}, sources: ["+bao2+"]}"),
		"through the built-in, admitted by a named source":           pg("ref+vault://kv/tresor/db#password", "{vault: {allow: [{mount: secret}]}, sources: ["+bao2+"]}"),
		"through one named source, admitted by another":              pg("ref+us1://secret/db#password", "{sources: ["+own("us1")+", "+strings.Replace(own("us2"), "mount: kv", "mount: secret", 1)+"]}"),
		"Key Vault through the built-in, admitted by a named source": pg("ref+azkv://kv2/db", "{azkv: {allow: [{vault: kv1}]}, sources: [{name: p, kind: azkv, azure: {identity: workload, client_id: c}, allow: [{vault: kv2}]}]}"),
	} {
		if _, err := Parse([]byte(doc)); err == nil || !strings.Contains(err.Error(), "allowlist") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Parse([]byte(pg("ref+bao2://other/tresor/db#password", "{vault: {allow: [{mount: secret}]}, sources: ["+bao2+"]}"))); err != nil {
		t.Fatalf("outside every allowlist: %v", err)
	}
	// a source's own identity names its client id: none is the system-assigned or the webhook's, likely the
	// top-level one
	for _, id := range []string{"{identity: managed}", "{identity: workload, tenant_id: t}"} {
		if _, err := Parse([]byte(good + top + "material: {sources: [{name: p, kind: azkv, azure: " + id + ", allow: [{vault: kv2}]}]}\n")); err == nil {
			t.Errorf("%s: accepted", id)
		}
	}
}

// the console (spec 010): on by default, origins as a browser sends them
func TestUI(t *testing.T) {
	cfg, err := Parse([]byte(good))
	if err != nil || !cfg.UI.On() || cfg.UI.Environment != "" {
		t.Fatalf("defaults: %+v %v", cfg.UI, err)
	}
	ok := good + "ui: {environment: prod, allowed_origins: ['https://platform.corp.example', 'http://localhost:5173'], frame_ancestors: ['https://platform.corp.example:8443']}\n"
	if cfg, err := Parse([]byte(ok)); err != nil || cfg.UI.Environment != "prod" {
		t.Fatalf("%v", err)
	}
	if cfg, _ := Parse([]byte(good + "ui: {enabled: false}\n")); cfg.UI.On() {
		t.Fatal("enabled: false")
	}
	for _, d := range []string{
		"ui: {allowed_origins: ['https://platform.corp.example/']}",
		"ui: {allowed_origins: ['https://platform.corp.example/ui']}",
		"ui: {allowed_origins: ['http://platform.corp.example']}",
		"ui: {allowed_origins: ['*']}",
		"ui: {allowed_origins: ['https://Platform.corp.example']}",
		"ui: {frame_ancestors: ['https://a.example?x=1']}",
		"ui: {environment: '<b>prod</b>'}",
		"ui: {environment: 'a very long environment label, more than 32'}",
	} {
		if _, err := Parse([]byte(good + d + "\n")); err == nil {
			t.Errorf("%s: accepted", d)
		}
	}
}
