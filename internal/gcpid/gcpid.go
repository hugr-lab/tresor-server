// Package gcpid is the service's own identity on GCP (spec 012): Application Default Credentials - GKE Workload
// Identity or a VM's service account (the metadata server), or workload identity federation (an external
// account). A service account key or a user's login is a static secret: refused unless allowed (development,
// tests). No secret of the service's own.
package gcpid

import (
	"context"
	"encoding/json"
	"fmt"

	"golang.org/x/oauth2/google"
)

// Scope is every GCP API's: the service account's IAM roles say what it may do.
const Scope = "https://www.googleapis.com/auth/cloud-platform"

// Credentials returns the service's credentials for scopes (Scope when none).
func Credentials(ctx context.Context, allowStatic bool, scopes ...string) (*google.Credentials, error) {
	if len(scopes) == 0 {
		scopes = []string{Scope}
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
	case "external_account", "impersonated_service_account":
		// federation, or a service account impersonated by another identity: no key of its own - but an
		// impersonation whose source is itself a key is judged by its source
		if f.Type == "impersonated_service_account" {
			var imp struct {
				Source json.RawMessage `json:"source_credentials"`
			}
			if json.Unmarshal(file, &imp) == nil && len(imp.Source) > 0 {
				return Static(imp.Source)
			}
		}
		return ""
	case "service_account":
		return "service account key"
	case "authorized_user":
		return "user's login (gcloud)"
	}
	return f.Type + " credentials file"
}
