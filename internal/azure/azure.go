// Package azure is the service's own identity on Azure (specs 002, 003): a managed identity where the platform
// has one (Container Apps), the pod's federated identity on AKS (workload identity), or DefaultAzureCredential
// for development (the az CLI's login). No secret of the service's own.
package azure

import (
	"errors"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Identity says how the service authenticates to Azure.
type Identity struct {
	// Kind: managed (a managed identity), workload (AKS workload identity: the pod's ServiceAccount token,
	// federated) or default (DefaultAzureCredential: environment, workload identity, managed identity, the az
	// CLI).
	Kind string
	// ClientID names a user-assigned managed identity (managed; empty: the system-assigned one), or overrides
	// the webhook's AZURE_CLIENT_ID (workload).
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
	case "workload":
		// the AKS webhook injects these into a pod labelled azure.workload.identity/use: "true" whose
		// ServiceAccount carries azure.workload.identity/client-id
		for _, v := range []string{"AZURE_TENANT_ID", "AZURE_FEDERATED_TOKEN_FILE"} {
			if os.Getenv(v) == "" {
				return nil, fmt.Errorf("azure.identity: workload: %s is not set - label the pod "+
					"azure.workload.identity/use: \"true\" and annotate its ServiceAccount with "+
					"azure.workload.identity/client-id", v)
			}
		}
		if _, err := os.Stat(os.Getenv("AZURE_FEDERATED_TOKEN_FILE")); err != nil {
			return nil, errors.New("azure.identity: workload: AZURE_FEDERATED_TOKEN_FILE does not read - is the " +
				"projected token mounted?")
		}
		if id.ClientID == "" && os.Getenv("AZURE_CLIENT_ID") == "" {
			return nil, errors.New("azure.identity: workload: no client id - annotate the ServiceAccount with " +
				"azure.workload.identity/client-id, or set azure.client_id")
		}
		return azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{ClientID: id.ClientID})
	case "default":
		if id.ClientID != "" {
			return nil, fmt.Errorf("azure.client_id is for identity: managed or workload; the default credential reads AZURE_CLIENT_ID")
		}
		return azidentity.NewDefaultAzureCredential(nil)
	}
	return nil, fmt.Errorf("azure.identity is managed, workload or default")
}
