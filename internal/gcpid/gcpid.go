// Package gcpid is the service's own identity on GCP (spec 012): Application Default Credentials - GKE Workload
// Identity or a VM's service account (the metadata server), or workload identity federation (an external
// account). A service account key or a user's login is a static secret: refused unless allowed (development,
// tests). No secret of the service's own.
package gcpid

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/oauth2/google"
)

// Scope is every GCP API's: the service account's IAM roles say what it may do.
const Scope = "https://www.googleapis.com/auth/cloud-platform"

// Universe is the only GCP universe the service calls: the clients are pinned to it, and the environment may not
// name another (an endpoint elsewhere would receive the token and every data key).
const Universe = "googleapis.com"

// steering are the environment's ways to send the clients or their token elsewhere, or to run a program for them.
var steering = []string{"GOOGLE_API_GO_EXPERIMENTAL_DISABLE_NEW_AUTH_LIB", "GCE_METADATA_HOST", "GCE_METADATA_IP",
	"GOOGLE_API_USE_CLIENT_CERTIFICATE", "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"}

// Environment refuses what would steer the GCP clients: another universe, another metadata server, the old auth
// path that checks no universe, a client certificate's signer program, an executable credential source.
func Environment() error {
	if u := os.Getenv("GOOGLE_CLOUD_UNIVERSE_DOMAIN"); u != "" && u != Universe {
		return fmt.Errorf("GOOGLE_CLOUD_UNIVERSE_DOMAIN names another universe: the service calls %s only", Universe)
	}
	for _, v := range steering {
		if os.Getenv(v) != "" {
			return fmt.Errorf("%s is set: the GCP clients' endpoints, metadata server and credentials come from the platform only", v)
		}
	}
	return nil
}

// Credentials returns the service's credentials for scopes (Scope when none).
func Credentials(ctx context.Context, allowStatic bool, scopes ...string) (*google.Credentials, error) {
	if len(scopes) == 0 {
		scopes = []string{Scope}
	}
	if err := Environment(); err != nil {
		return nil, err
	}
	creds, err := google.FindDefaultCredentials(ctx, scopes...)
	if err != nil {
		return nil, fmt.Errorf("the GCP credentials (Application Default Credentials): %w", err)
	}
	if kind := Static(creds.JSON); kind != "" && !allowStatic {
		return nil, fmt.Errorf("the GCP credentials are a %s (a static secret): the service uses the platform's "+
			"identity (GKE Workload Identity, a VM's service account, workload identity federation); "+
			"gcp.static_credentials: allow is for tests", kind)
	}
	if u, err := creds.GetUniverseDomain(); err == nil && u != Universe {
		return nil, fmt.Errorf("the GCP credentials are for another universe: the service calls %s only", Universe)
	}
	return creds, nil
}

// Static names the kind of static secret a credentials file is ("service_account" with a key, "authorized_user"
// a person's login), or "" for none: the metadata server's (no file), an external account's (federation).
func Static(file []byte) string {
	if len(file) == 0 {
		return ""
	}
	var f struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(file, &f) != nil {
		return "credentials file that does not parse"
	}
	switch f.Type {
	case "external_account":
		// federation - unless its subject token is AWS's from static keys, or a program's output
		var ea struct {
			Source struct {
				EnvironmentID string          `json:"environment_id"`
				Executable    json.RawMessage `json:"executable"`
			} `json:"credential_source"`
		}
		_ = json.Unmarshal(file, &ea)
		if len(ea.Source.Executable) > 0 {
			return "federation through a program (an executable credential source)"
		}
		if strings.HasPrefix(ea.Source.EnvironmentID, "aws") {
			for _, v := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY", "AWS_SECRET_KEY"} {
				if os.Getenv(v) != "" {
					return "federation from static AWS keys (" + v + ")"
				}
			}
		}
		return ""
	case "impersonated_service_account":
		// a service account impersonated by another identity: judged by that identity
		var imp struct {
			Source json.RawMessage `json:"source_credentials"`
		}
		if json.Unmarshal(file, &imp) == nil && len(imp.Source) > 0 && string(imp.Source) != "null" {
			return Static(imp.Source)
		}
		return "impersonation with no source"
	case "service_account":
		return "service account key"
	case "authorized_user":
		return "user's login (gcloud)"
	}
	if f.Type == "" {
		return "credentials file of no type"
	}
	return f.Type + " credentials file"
}
