package gcpid

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatic(t *testing.T) {
	for file, want := range map[string]string{
		``:                            "",
		`{"type":"external_account"}`: "",
		`{"type":"service_account"}`:  "service account key",
		`{"type":"authorized_user"}`:  "user's login (gcloud)",
		`{"type":"impersonated_service_account","source_credentials":{"type":"authorized_user"}}`:  "user's login (gcloud)",
		`{"type":"impersonated_service_account","source_credentials":{"type":"external_account"}}`: "",
		`{"type":"gdch_service_account"}`:             "gdch_service_account credentials file",
		`not json`:                                    "credentials file that does not parse",
		`{"installed":{"client_id":"c"}}`:             "credentials file of no type",
		`{"type":"external_account_authorized_user"}`: "external_account_authorized_user credentials file",
		`{"type":"external_account","credential_source":{"executable":{"command":"/bin/x"}}}`: "federation through a program (an executable credential source)",
		`{"type":"impersonated_service_account","source_credentials":null}`:                   "impersonation with no source",
	} {
		if got := Static([]byte(file)); got != want {
			t.Errorf("%s: %q, want %q", file, got, want)
		}
	}
}

// a person's gcloud login through GOOGLE_APPLICATION_CREDENTIALS: refused, unless allowed
func TestCredentialsRefuseAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "adc.json")
	if err := os.WriteFile(file, []byte(`{"type":"authorized_user","client_id":"c","client_secret":"never-in-an-error","refresh_token":"r"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", file)
	_, err := Credentials(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "user's login") || strings.Contains(err.Error(), "never-in-an-error") {
		t.Fatalf("refused: %v", err)
	}
	if _, err := Credentials(context.Background(), true); err != nil {
		t.Fatalf("allowed: %v", err)
	}
}

// federation from AWS: refused when static AWS keys would be its source
func TestStaticAWSFederation(t *testing.T) {
	file := []byte(`{"type":"external_account","credential_source":{"environment_id":"aws1"}}`)
	if got := Static(file); got != "" {
		t.Fatalf("an instance's role: %q", got)
	}
	t.Setenv("AWS_SECRET_KEY", "x")
	if got := Static(file); got == "" {
		t.Fatal("static AWS keys as the source: accepted")
	}
}

// the environment may not steer the clients: another universe, metadata server, the old auth path, a program
func TestEnvironment(t *testing.T) {
	if err := Environment(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_CLOUD_UNIVERSE_DOMAIN", Universe)
	if err := Environment(); err != nil {
		t.Fatalf("googleapis.com named: %v", err)
	}
	for k, v := range map[string]string{"GOOGLE_CLOUD_UNIVERSE_DOMAIN": "evil.invalid", "GCE_METADATA_HOST": "10.0.0.9",
		"GOOGLE_API_GO_EXPERIMENTAL_DISABLE_NEW_AUTH_LIB": "true", "GOOGLE_API_USE_CLIENT_CERTIFICATE": "true",
		"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES": "1"} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if err := Environment(); err == nil || !strings.Contains(err.Error(), k) {
				t.Fatalf("%s: %v", k, err)
			}
		})
	}
}
