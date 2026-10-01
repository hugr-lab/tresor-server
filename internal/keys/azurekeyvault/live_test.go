//go:build live

package azurekeyvault

// A live run against a real Key Vault key (scripts/dev/azure_live.sh), with the developer's az CLI login:
//
//	TRESOR_LIVE_KEK=https://<vault>.vault.azure.net/keys/<name> go test -tags live -run Live ./internal/keys/azurekeyvault

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/hugr-lab/tresor-server/internal/azure"
	"github.com/hugr-lab/tresor-server/internal/keys"
)

func TestLive(t *testing.T) {
	keyURL := os.Getenv("TRESOR_LIVE_KEK")
	if keyURL == "" {
		t.Skip("TRESOR_LIVE_KEK names no key")
	}
	cred, err := azure.Credential(azure.Identity{Kind: "default"})
	if err != nil {
		t.Fatal(err)
	}
	w, err := New(keyURL, cred)
	if err != nil {
		t.Fatal(err)
	}
	store := &dataKeys{keys: map[string]keys.DataKey{}}
	e := keys.NewEnvelope(w, store, keys.Options{})
	if err := e.Check(ctx); err != nil {
		t.Fatalf("the KEK: %v", err)
	}
	id, sealed, err := e.Seal(ctx, []byte("aad"), []byte("live-value"))
	if err != nil {
		t.Fatal(err)
	}
	fresh := keys.NewEnvelope(w, store, keys.Options{})
	if plain, err := fresh.Open(ctx, id, []byte("aad"), sealed); err != nil || string(plain) != "live-value" {
		t.Fatalf("open through the vault: %v", err)
	}
	// a rotation in the vault: a new data key, then rewrap moves the old one to the new version
	if os.Getenv("TRESOR_LIVE_ROTATE") == "1" {
		host, name, _ := ParseKeyURL(keyURL)
		vaultName := strings.TrimSuffix(host, ".vault.azure.net")
		if out, err := exec.Command("az", "keyvault", "key", "rotate", "--vault-name", vaultName, "--name", name,
			"-o", "none").CombinedOutput(); err != nil {
			t.Fatalf("az keyvault key rotate: %v %s", err, out)
		}
		w.readAt = time.Time{}
		second, _, err := e.Seal(ctx, nil, []byte("x"))
		if err != nil || second == id {
			t.Fatalf("after the rotation: %s %v", second, err)
		}
		if n, err := e.Rewrap(ctx, false, nil); err != nil || n != 1 {
			t.Fatalf("rewrap: %d %v", n, err)
		}
		if plain, err := keys.NewEnvelope(w, store, keys.Options{}).Open(ctx, id, []byte("aad"), sealed); err != nil ||
			string(plain) != "live-value" {
			t.Fatalf("an old value after rewrap: %v", err)
		}
	}
	t.Logf("sealed and opened through %s (%d data keys)", keyURL, len(store.keys))
}
