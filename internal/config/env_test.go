package config

import (
	"slices"
	"strings"
	"testing"
)

// every setting from the environment, no file (spec 002: containers, Kubernetes, Container Apps)
func TestEnvOnly(t *testing.T) {
	cfg, used, err := LoadFrom(nil, []string{
		"TRESOR_LISTEN=127.0.0.1:9443",
		"TRESOR_PUBLIC_URL=http://127.0.0.1:9443",
		"TRESOR_STATE__KIND=memory",
		"TRESOR_ISSUERS=[{issuer: 'https://idp.example/realms/x', audience: duckdb-secrets}]",
		"TRESOR_POLICY__ADMINS=[role:secrets_admin, client:etl]",
		"TRESOR_EXCHANGE_SECRET=not-a-setting", // a variable a setting names: left alone
		"TRESOR_SERVER_CMD=also-not",           // tresor's test runner's
		"PATH=/bin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9443" || cfg.State.Kind != "memory" || len(cfg.Issuers) != 1 ||
		cfg.Issuers[0].Audience != "duckdb-secrets" || !slices.Equal(cfg.Policy.Admins, []string{"role:secrets_admin", "client:etl"}) {
		t.Fatalf("from the environment: %+v", cfg)
	}
	want := FromEnv{"TRESOR_ISSUERS", "TRESOR_LISTEN", "TRESOR_POLICY__ADMINS", "TRESOR_PUBLIC_URL", "TRESOR_STATE__KIND"}
	if !slices.Equal(used, want) {
		t.Fatalf("names from the environment: %v", used)
	}
}

// the file, then TRESOR_CONFIG, then one variable per setting, each over the last
func TestEnvOverFile(t *testing.T) {
	cfg, used, err := LoadFrom([]byte(good), []string{
		"TRESOR_CONFIG=listen: 127.0.0.1:7000\npolicy: {admins: [role:from_document]}",
		"TRESOR_LISTEN=127.0.0.1:7001",
		"TRESOR_POLICY__ACTORS=[]",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:7001" {
		t.Fatalf("a variable over TRESOR_CONFIG over the file: %s", cfg.Listen)
	}
	// a section in TRESOR_CONFIG is merged key by key; a list is replaced whole
	if !slices.Equal(cfg.Policy.Admins, []string{"role:from_document"}) || len(cfg.Policy.Actors) != 0 {
		t.Fatalf("policy: %+v", cfg.Policy)
	}
	if cfg.PublicURL != "http://127.0.0.1:8443" || cfg.Issuers[0].Issuer == "" {
		t.Fatal("what no source overrides stays the file's")
	}
	if !slices.Equal(used, FromEnv{"TRESOR_CONFIG", "TRESOR_LISTEN", "TRESOR_POLICY__ACTORS"}) {
		t.Fatalf("used: %v", used)
	}
	// a whole section by one variable, then one of its keys by another
	cfg, _, err = LoadFrom([]byte(good), []string{"TRESOR_STATE={kind: etcd}", "TRESOR_STATE__KIND=memory"})
	if err != nil || cfg.State.Kind != "memory" {
		t.Fatalf("the deeper variable last: %v %+v", err, cfg)
	}
}

func TestEnvRefused(t *testing.T) {
	cases := map[string][]string{
		"an unknown key in a known section": {"TRESOR_STATE__KNID=memory"},
		"an unknown key in TRESOR_CONFIG":   {"TRESOR_CONFIG=extra: 1"},
		"TRESOR_CONFIG not a mapping":       {"TRESOR_CONFIG=[1, 2]"},
		"an empty level":                    {"TRESOR_STATE____KIND=memory"},
		"a value that is not YAML":          {"TRESOR_POLICY__ADMINS=[role:x"},
		"a value of the wrong type":         {"TRESOR_POLICY__ADMINS={a: b}"},
		"an invalid result":                 {"TRESOR_LISTEN=0.0.0.0:8443"}, // plain http off loopback
	}
	for name, env := range cases {
		if _, _, err := LoadFrom([]byte(good), env); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// no source at all: nothing to run with
	if _, _, err := LoadFrom(nil, nil); err == nil {
		t.Fatal("an empty configuration")
	}
}

// an error names the variable, never quotes its value: a secret put there by mistake stays out of the log
func TestEnvErrorsQuoteNoValue(t *testing.T) {
	for _, env := range [][]string{
		{"TRESOR_POLICY__ADMINS=[hunter2-secret"},
		{"TRESOR_POLICY__ADMINS={hunter2-secret: b}"},
		{"TRESOR_ISSUERS=[{issuer: 'https://idp.example', audience: a, audience_parameter: hunter2}]"},
		{"TRESOR_TLS=hunter2-secret"},
	} {
		_, _, err := LoadFrom([]byte(good), env)
		if err == nil || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%v: %v", env, err)
		}
	}
}
