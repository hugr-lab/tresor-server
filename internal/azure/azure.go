// Package azure is the service's own identity on Azure (spec 002): a managed identity where the platform
// has one (Container Apps, AKS), or DefaultAzureCredential for development (the az CLI's login). No secret of
// the service's own.
package azure

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Identity says how the service authenticates to Azure.
type Identity struct {
	// Kind: managed (a managed identity) or default (DefaultAzureCredential: environment, workload
	// identity, managed identity, the az CLI).
	Kind string
	// ClientID names a user-assigned managed identity; empty for the system-assigned one.
	ClientID string
}

// Credential returns the service's credential.
func Credential(id Identity) (azcore.TokenCredential, error) {
	switch id.Kind {
	case "managed":
		opts := &azidentity.ManagedIdentityCredentialOptions{}
		if id.ClientID != "" {
			opts.ID = azidentity.ClientID(id.ClientID)
		}
		return azidentity.NewManagedIdentityCredential(opts)
	case "default":
		if id.ClientID != "" {
			return nil, fmt.Errorf("azure.client_id is for identity: managed; the default credential reads AZURE_CLIENT_ID")
		}
		return azidentity.NewDefaultAzureCredential(nil)
	}
	return nil, fmt.Errorf("azure.identity is managed or default")
}
