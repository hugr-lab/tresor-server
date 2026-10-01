package azure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// workload identity reads what the AKS webhook injects; missing, it says what to set, never a guess
func TestWorkload(t *testing.T) {
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("a-projected-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000001")
	t.Setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000002")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", token)
	if _, err := Credential(Identity{Kind: "workload"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Credential(Identity{Kind: "workload", ClientID: "00000000-0000-0000-0000-000000000003"}); err != nil {
		t.Fatalf("a client id of its own: %v", err)
	}
	for _, unset := range []string{"AZURE_TENANT_ID", "AZURE_FEDERATED_TOKEN_FILE", "AZURE_CLIENT_ID"} {
		t.Run(unset, func(t *testing.T) {
			t.Setenv(unset, "")
			if _, err := Credential(Identity{Kind: "workload"}); err == nil || !strings.Contains(err.Error(), "azure.workload.identity") {
				t.Fatalf("with %s unset: %v", unset, err)
			}
		})
	}
	if _, err := Credential(Identity{Kind: "federated"}); err == nil {
		t.Fatal("an unknown kind")
	}
}
