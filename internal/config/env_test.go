package config

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

// setenv sets the environment for one test (t.Setenv restores it) and clears every other TRESOR_ variable.
func setenv(t *testing.T, env ...string) {
	t.Helper()
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(strings.ToUpper(name), envPrefix) {
			t.Setenv(name, "")
			os.Unsetenv(name)
		}
	}
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		t.Setenv(name, value)
	}
}

func loadEnv(file string) (*Config, FromEnv, error) { return load([]byte(file), true) }

// every setting from the environment, no file (spec 002: containers, Kubernetes, Container Apps)
func TestEnvOnly(t *testing.T) {
	setenv(t,
		"TRESOR_LISTEN=127.0.0.1:9443",
		"TRESOR_PUBLIC_URL=http://127.0.0.1:9443",
		"TRESOR_STATE__KIND=memory",
		"TRESOR_ISSUERS=[{issuer: 'https://idp.example/realms/x', audience: duckdb-secrets}]",
		"TRESOR_POLICY__ADMINS=[role:secrets_admin, client:etl]",
		"TRESOR_EXCHANGE_SECRET=not-a-setting", // a variable a setting names: left alone
		"TRESOR_SERVER_CMD=also-not",           // tresor's test runner's
	)
	cfg, used, err := loadEnv("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9443" || cfg.State.Kind != "memory" || len(cfg.Issuers) != 1 ||
		cfg.Issuers[0].Audience != "duckdb-secrets" || cfg.Issuers[0].Algorithms == nil ||
		!slices.Equal(cfg.Policy.Admins, []string{"role:secrets_admin", "client:etl"}) {
		t.Fatalf("from the environment: %+v", cfg)
	}
	want := FromEnv{"TRESOR_ISSUERS", "TRESOR_LISTEN", "TRESOR_POLICY__ADMINS", "TRESOR_PUBLIC_URL", "TRESOR_STATE__KIND"}
	if !slices.Equal(used, want) {
		t.Fatalf("names from the environment: %v", used)
	}
}

// the file, then TRESOR_CONFIG, then one variable per setting, each over the last
func TestEnvOverFile(t *testing.T) {
	setenv(t,
		"TRESOR_CONFIG=listen: 127.0.0.1:7000\npolicy: {admins: [role:from_document]}",
		"TRESOR_LISTEN=127.0.0.1:7001",
		"TRESOR_POLICY__ACTORS=[]",
	)
	cfg, used, err := loadEnv(good)
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
	if cfg.PublicURL != "http://127.0.0.1:8443" || cfg.Issuers[0].Issuer == "" || cfg.State.Kind != "memory" {
		t.Fatal("what no source overrides stays the file's")
	}
	if !slices.Equal(used, FromEnv{"TRESOR_CONFIG", "TRESOR_LISTEN", "TRESOR_POLICY__ACTORS"}) {
		t.Fatalf("used: %v", used)
	}
}

// a text setting takes its variable as it is: a URL with a fragment, values YAML would read otherwise
func TestEnvTextVerbatim(t *testing.T) {
	setenv(t,
		"TRESOR_PUBLIC_URL=http://127.0.0.1:8443/base #kept",
		"TRESOR_TLS__CERT=&anchor-like",
		"TRESOR_TLS__KEY=null",
	)
	cfg, _, err := loadEnv(good)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "http://127.0.0.1:8443/base #kept" || cfg.TLS.Cert != "&anchor-like" || cfg.TLS.Key != "null" {
		t.Fatalf("text settings as they came: %+v", cfg)
	}
}

func TestEnvRefused(t *testing.T) {
	cases := map[string][]string{
		"an unknown key in a known section": {"TRESOR_STATE__KNID=memory"},
		"an unknown key in TRESOR_CONFIG":   {"TRESOR_CONFIG=extra: 1"},
		"TRESOR_CONFIG not a mapping":       {"TRESOR_CONFIG=[1, 2]"},
		"one _ for a level":                 {"TRESOR_STATE_KIND=memory"},
		"a section's typo":                  {"TRESOR_POLICIES__ADMINS=[x]"},
		"a list's item":                     {"TRESOR_ISSUERS__0__ISSUER=https://x"},
		"a section whole":                   {"TRESOR_STATE={kind: memory}"},
		"a name not in capitals":            {"TRESOR_state__kind=memory"},
		"a value that is not YAML":          {"TRESOR_POLICY__ADMINS=[role:x"},
		"a value of the wrong type":         {"TRESOR_POLICY__ADMINS={a: b}"},
		"an invalid result":                 {"TRESOR_LISTEN=0.0.0.0:8443"}, // plain http off loopback
		"the reference server's store":      {"TRESOR_CONFIG=store:"},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			setenv(t, env...)
			if _, _, err := loadEnv(good); err == nil {
				t.Errorf("accepted")
			}
		})
	}
}

func TestEnvNothing(t *testing.T) {
	setenv(t, "TRESOR_KEK=x")
	if _, _, err := loadEnv(""); !errors.Is(err, ErrEmpty) {
		t.Fatalf("no configuration: %v", err)
	}
}

// an error never quotes a value: a secret put in the wrong place stays out of the log
func TestEnvErrorsQuoteNoValue(t *testing.T) {
	for _, env := range [][]string{
		{"TRESOR_POLICY__ADMINS=[hunter2-secret"},
		{"TRESOR_POLICY__ADMINS={hunter2-secret: b}"},
		{"TRESOR_ISSUERS=[{issuer: 'https://idp.example', audience: a, audience_parameter: hunter2}]"},
		{"TRESOR_TLS=hunter2-secret"},
		{"TRESOR_POLICY__ADMINS=[\"hunter2`abcdefghij\"]", "TRESOR_TLS__CERT=x"},
		{"TRESOR_STATE__KIND=hunter2secret"},
		{"TRESOR_CONFIG=listen: \"hunter2\\q\""},
		{"TRESOR_CONFIG=listen: [hunter2"},
	} {
		setenv(t, env...)
		_, _, err := loadEnv(good)
		if err == nil || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%v: %v", env, err)
		}
	}
}

// the file's anchors resolve, and survive a variable over the anchored setting
func TestEnvOverAnchor(t *testing.T) {
	setenv(t, "TRESOR_LISTEN=127.0.0.1:2")
	doc := "listen: &l 127.0.0.1:8443\npublic_url: http://127.0.0.1:8443\nstate: {kind: memory}\n" +
		"issuers: [{issuer: 'https://idp.example', audience: a, client_id: *l}]\n"
	cfg, _, err := loadEnv(doc)
	if err != nil || cfg.Issuers[0].ClientID != "127.0.0.1:8443" || cfg.Listen != "127.0.0.1:2" {
		t.Fatalf("an alias to an overridden anchor: %v %+v", err, cfg)
	}
}

// a *_env setting must not name a variable read as configuration: its secret would be configuration too
func TestSecretVariableNotASetting(t *testing.T) {
	with := strings.Replace(good, "audience: duckdb-secrets",
		"audience: duckdb-secrets\n    exchange: {client_id: c, client_secret_env: TRESOR_LISTEN}", 1)
	t.Setenv("TRESOR_LISTEN", "127.0.0.1:8443")
	if _, err := Parse([]byte(with)); err == nil || !strings.Contains(err.Error(), "read as configuration") {
		t.Fatalf("a secret in a setting's variable: %v", err)
	}
}
