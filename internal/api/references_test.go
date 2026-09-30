package api

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/hugr-lab/tresor-server/internal/material"
	azkv "github.com/hugr-lab/tresor-server/internal/material/azurekeyvault"
)

// kvSecrets is a vault's secrets for the API's tests
type kvSecrets struct {
	values map[string]string
	down   atomic.Bool
}

func (v *kvSecrets) GetSecret(_ context.Context, name, _ string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	if v.down.Load() {
		return azsecrets.GetSecretResponse{}, &azcore.ResponseError{StatusCode: 503, ErrorCode: "ServiceUnavailable"}
	}
	value, ok := v.values[name]
	if !ok {
		return azsecrets.GetSecretResponse{}, &azcore.ResponseError{StatusCode: 404, ErrorCode: "SecretNotFound"}
	}
	id := azsecrets.ID("https://corp-vault.vault.azure.net/secrets/" + name + "/00000000000000000000000000000007")
	return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{ID: &id, Value: &value}}, nil
}

func withVault(f *fixture, v *kvSecrets, allow ...azkv.Allow) {
	f.srv.material = material.New(azkv.NewWithGetter(allow, func(string) (azkv.Getter, error) { return v, nil }, azkv.Options{}))
}

const refSecret = `{"type":"s3","provider":"config","scope":["s3://lake"],
  "params":{"key_id":"AKIA","secret":{"type":"VARCHAR","value":"ref+azkv://corp-vault/lake-s3"}},"redact_keys":[]}`

// a secret whose material stays in Key Vault: written by an admin as a reference, read at each fetch with the
// service's identity, the value never stored, never logged
func TestReferences(t *testing.T) {
	f := newFixture(t, "")
	v := &kvSecrets{values: map[string]string{"lake-s3": "hunter2-from-the-vault"}}
	withVault(f, v, azkv.Allow{Vault: "corp-vault", Prefixes: []string{"lake-"}})
	r := f.do("PUT", "/v1/secrets/lake", f.admin, refSecret)
	if r.status != 201 {
		t.Fatalf("a reference within the allowlist: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/lake/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	r = f.do("GET", "/v1/secrets/lake", f.alice, "")
	body := r.json(t)
	secret := body["params"].(map[string]any)["secret"].(map[string]any)
	if r.status != 200 || secret["value"] != "hunter2-from-the-vault" || secret["type"] != "VARCHAR" {
		t.Fatalf("resolved at the fetch: %d %s", r.status, r.body)
	}
	if redact := body["redact_keys"].([]any); len(redact) != 1 || redact[0] != "secret" {
		t.Fatalf("a reference's parameter is redacted: %v", redact)
	}
	// a rotation in the vault reaches the next fetch
	v.values["lake-s3"] = "rotated"
	if r := f.do("GET", "/v1/secrets/lake", f.alice, ""); !strings.Contains(string(r.body), `"rotated"`) {
		t.Fatalf("after a rotation: %s", r.body)
	}
	logs := f.logs.String()
	if !strings.Contains(logs, "reference resolved") || !strings.Contains(logs, "ref+azkv://corp-vault/lake-s3") ||
		!strings.Contains(logs, "00000000000000000000000000000007") {
		t.Fatal("each resolution is logged: the secret, the reference, the version")
	}
	if strings.Contains(logs, "hunter2") || strings.Contains(logs, "rotated") {
		t.Fatal("a resolved value reached the log")
	}
	// the vault down: 503 for this fetch - never an empty or a stale value
	v.down.Store(true)
	if r := f.do("GET", "/v1/secrets/lake", f.alice, ""); r.status != 503 || strings.Contains(string(r.body), "rotated") {
		t.Fatalf("the vault down: %d %s", r.status, r.body)
	}
	v.down.Store(false)
	// the allowlist narrowed after the write: the stored reference no longer resolves
	withVault(f, v, azkv.Allow{Vault: "other-vault"})
	if r := f.do("GET", "/v1/secrets/lake", f.alice, ""); r.status != 503 {
		t.Fatalf("outside the narrowed allowlist: %d %s", r.status, r.body)
	}
	// the descriptor needs no resolution: a list still answers
	if r := f.do("GET", "/v1/secrets", f.alice, ""); r.status != 200 {
		t.Fatalf("the list: %d", r.status)
	}
}

func TestReferencesRefused(t *testing.T) {
	f := newFixture(t, "")
	for name, value := range map[string]string{
		"outside the allowlist": "ref+azkv://corp-vault/other-secret",
		"another vault":         "ref+azkv://evil-vault/lake-s3",
		"an escape":             "ref+azkv://corp-vault/lake-s3%2f..",
		"an unknown scheme":     "ref+vault://corp/lake",
	} {
		withVault(f, &kvSecrets{}, azkv.Allow{Vault: "corp-vault", Prefixes: []string{"lake-"}})
		doc := strings.Replace(refSecret, "ref+azkv://corp-vault/lake-s3", value, 1)
		if r := f.do("PUT", "/v1/secrets/x", f.admin, doc); r.status != 422 || r.problemType(t) != "invalid_secret" {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	// shapes a client reads otherwise than this service, or near misses: refused, never stored as literals
	for name, param := range map[string]string{
		"VALUE in capitals":   `{"type":"VARCHAR","VALUE":"ref+azkv://evil-vault/x","value":"lit"}`,
		"TYPE in capitals":    `{"type":"BLOB","TYPE":"VARCHAR","value":"ref+azkv://corp-vault/lake-s3"}`,
		"a repeated key":      `{"type":"VARCHAR","value":"ref+azkv://evil-vault/x","value":"lit"}`,
		"REF+ in capitals":    `"REF+azkv://evil-vault/x"`,
		"a space before ref+": `" ref+azkv://evil-vault/x"`,
	} {
		withVault(f, &kvSecrets{}, azkv.Allow{Vault: "corp-vault", Prefixes: []string{"lake-"}})
		doc := `{"type":"s3","provider":"config","params":{"secret":` + param + `},"redact_keys":[]}`
		if r := f.do("PUT", "/v1/secrets/x", f.admin, doc); r.status != 422 {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	// a scheme that is not one is not quoted back: it may be a value written by mistake
	doc := strings.Replace(refSecret, "ref+azkv://corp-vault/lake-s3", "ref+HUNTER2value://x", 1)
	if r := f.do("PUT", "/v1/secrets/x", f.admin, doc); r.status != 422 || strings.Contains(string(r.body), "HUNTER2") {
		t.Errorf("a scheme quoted back: %d %s", r.status, r.body)
	}
	// no material: configured - every reference refused, never stored as a literal
	f.srv.material = nil
	if r := f.do("PUT", "/v1/secrets/x", f.admin, refSecret); r.status != 422 {
		t.Fatalf("no sources: %d %s", r.status, r.body)
	}
}
