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
		`{"type":"gdch_service_account"}`: "gdch_service_account credentials file",
		`not json`:                        "credentials file that does not parse",
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
