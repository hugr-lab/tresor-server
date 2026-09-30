package config

import (
	"errors"
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
		"one _ for a level":                 {"TRESOR_STATE_KIND=memory"},
		"a section's typo":                  {"TRESOR_POLICIES__ADMINS=[x]"},
		"a list's item":                     {"TRESOR_ISSUERS__0__ISSUER=https://x"},
		"under a text setting":              {"TRESOR_LISTEN__X=1"},
		"one setting twice, in two cases":   {"TRESOR_STATE__KIND=memory", "TRESOR_state__kind=memory"},
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
		{"TRESOR_POLICY__ADMINS=[\"hunter2`abcdefghij\"]", "TRESOR_TLS=x"},
		{"TRESOR_POLICY__ADMINS={a: \"hun`ter2abcdef\"}"},
		{"TRESOR_STATE__KIND=hunter2secret"},
		{"TRESOR_CONFIG=listen: \"hunter2\\q\""},
	} {
		_, _, err := LoadFrom([]byte(good), env)
		if err == nil || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%v: %v", env, err)
		}
	}
}

// a text setting takes its variable as it is: a URL with a fragment, a value YAML would read otherwise
func TestEnvTextVerbatim(t *testing.T) {
	cfg, _, err := LoadFrom([]byte(good), []string{
		"TRESOR_ISSUERS=[{issuer: 'https://idp.example', audience: a, client_id: '*x'}]",
		"TRESOR_PUBLIC_URL=http://127.0.0.1:8443/base #kept",
		"TRESOR_TLS__CERT=&anchor-like",
		"TRESOR_TLS__KEY=null",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "http://127.0.0.1:8443/base #kept" || cfg.TLS.Cert != "&anchor-like" || cfg.TLS.Key != "null" ||
		cfg.Issuers[0].ClientID != "*x" {
		t.Fatalf("text settings as they came: %+v", cfg)
	}
	cfg, _, err = LoadFrom([]byte(good), []string{"TRESOR_PUBLIC_URL=http://127.0.0.1:8443/p#frag", "TRESOR_LISTEN=127.0.0.1:1"})
	if err != nil || cfg.PublicURL != "http://127.0.0.1:8443/p#frag" {
		t.Fatalf("a URL with a fragment: %v %q", err, cfg.PublicURL)
	}
}

// the file's anchors survive a variable over the anchored setting
func TestEnvOverAnchor(t *testing.T) {
	file := strings.Replace(good, "listen: 127.0.0.1:8443", "listen: &l 127.0.0.1:8443\nx_anchor_user: *l", 1)
	file = strings.Replace(file, "x_anchor_user: *l\n", "", 1) // an alias elsewhere would be an unknown key; the anchor alone
	if _, _, err := LoadFrom([]byte(file), []string{"TRESOR_LISTEN=127.0.0.1:2"}); err != nil {
		t.Fatal(err)
	}
	doc := "listen: &l 127.0.0.1:8443\npublic_url: http://127.0.0.1:8443\nstate: {kind: memory}\n" +
		"issuers: [{issuer: 'https://idp.example', audience: a, client_id: *l}]\n"
	cfg, _, err := LoadFrom([]byte(doc), []string{"TRESOR_LISTEN=127.0.0.1:2"})
	if err != nil || cfg.Issuers[0].ClientID != "127.0.0.1:8443" || cfg.Listen != "127.0.0.1:2" {
		t.Fatalf("an alias to an overridden anchor: %v %+v", err, cfg)
	}
}

func TestEnvNothing(t *testing.T) {
	if _, _, err := LoadFrom(nil, []string{"PATH=/bin", "TRESOR_KEK=x"}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("no configuration: %v", err)
	}
}

// a *_env setting must not name a variable read as configuration: its secret would be configuration too
func TestSecretVariableNotASetting(t *testing.T) {
	with := strings.Replace(good, "audience: duckdb-secrets",
		"audience: duckdb-secrets\n    exchange: {client_id: c, client_secret_env: TRESOR_STATE}", 1)
	t.Setenv("TRESOR_STATE", "x")
	if _, err := Parse([]byte(with)); err == nil || !strings.Contains(err.Error(), "read as configuration") {
		t.Fatalf("a secret in a setting's variable: %v", err)
	}
}
