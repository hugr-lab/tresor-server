//go:build live

package azurekeyvault

// A live run against a real Key Vault secret (scripts/dev/azure_live.sh), with the developer's az CLI login:
//
//	TRESOR_LIVE_VAULT=<vault> TRESOR_LIVE_SECRET=<name> TRESOR_LIVE_SECRET_SHA=<sha256 of its value> \
//	  go test -tags live -run Live ./internal/material/azurekeyvault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/hugr-lab/tresor-server/internal/azure"
)

func TestLive(t *testing.T) {
	vaultName, name := os.Getenv("TRESOR_LIVE_VAULT"), os.Getenv("TRESOR_LIVE_SECRET")
	if vaultName == "" || name == "" {
		t.Skip("TRESOR_LIVE_VAULT / TRESOR_LIVE_SECRET name no secret")
	}
	cred, err := azure.Credential(azure.Identity{Kind: "default"})
	if err != nil {
		t.Fatal(err)
	}
	s := New([]Allow{{Vault: vaultName, Prefixes: []string{"duckdb-"}}}, cred, Options{})
	ref, err := s.Parse(vaultName + "/" + name)
	if err != nil {
		t.Fatal(err)
	}
	value, version, err := s.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("resolving %s: %v", ref, err)
	}
	sum := sha256.Sum256([]byte(value))
	if hex.EncodeToString(sum[:]) != os.Getenv("TRESOR_LIVE_SECRET_SHA") {
		t.Fatal("the value read is not the one written") // compared by hash: the value is never printed
	}
	if _, err := s.Parse(vaultName + "/not-allowed"); err == nil {
		t.Fatal("a name outside the prefixes parsed")
	}
	t.Logf("resolved %s, version %s", ref, version)
}
