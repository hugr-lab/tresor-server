package azurekeyvault

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// vault is a Key Vault's secrets: name -> value, the current version, and whether they answer
type vault struct {
	url      string
	secrets  map[string]string
	disabled map[string]bool
	down     atomic.Bool
	reads    atomic.Int32
}

func (v *vault) GetSecret(_ context.Context, name, version string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	v.reads.Add(1)
	if v.down.Load() {
		return azsecrets.GetSecretResponse{}, &azcore.ResponseError{StatusCode: 503, ErrorCode: "ServiceUnavailable"}
	}
	value, ok := v.secrets[name]
	if !ok {
		return azsecrets.GetSecretResponse{}, &azcore.ResponseError{StatusCode: 404, ErrorCode: "SecretNotFound"}
	}
	if version == "" {
		version = "0123456789abcdef0123456789abcdef"
	}
	id := azsecrets.ID(v.url + "/secrets/" + name + "/" + version)
	enabled := !v.disabled[name]
	return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{ID: &id, Value: &value,
		Attributes: &azsecrets.SecretAttributes{Enabled: &enabled}}}, nil
}

func source(t *testing.T, v *vault, opts Options) *Source {
	t.Helper()
	return NewWithGetter([]Allow{{Vault: "corp-vault", Prefixes: []string{"lake-", "DuckDB-"}}, {Vault: "open-vault"}},
		func(vaultURL string) (Getter, error) {
			if vaultURL != v.url {
				t.Fatalf("a getter for %s, want %s", vaultURL, v.url)
			}
			return v, nil
		}, opts)
}

func TestParse(t *testing.T) {
	s := source(t, &vault{url: "https://corp-vault.vault.azure.net"}, Options{})
	for text, want := range map[string]string{
		"corp-vault/lake-s3": "ref+azkv://corp-vault/lake-s3",
		"Corp-Vault/LAKE-s3": "ref+azkv://corp-vault/LAKE-s3", // names without case, as Key Vault has them
		"corp-vault/duckdb-x/0123456789ABCDEF0123456789abcdef": "ref+azkv://corp-vault/duckdb-x/0123456789abcdef0123456789abcdef",
		"open-vault/anything": "ref+azkv://open-vault/anything",
	} {
		ref, err := s.Parse(text)
		if err != nil || ref.String() != want {
			t.Errorf("%s: %s %v", text, ref, err)
		}
	}
	for _, text := range []string{
		"corp-vault/other-secret",          // outside the prefixes
		"evil-vault/lake-s3",               // outside the vaults
		"corp-vault/lake-s3%2f..%2fx",      // an escape
		"corp-vault/lake-s3?api-version=1", // a query
		"corp-vault/lake-s3#x",
		"corp-vault/lake-s3/1234",      // not a version
		"corp-vault/lake-s3/v/extra",   // another segment
		"corp.vault.azure.net/lake-s3", // a host, not a vault's name
		"corp-vault/", "/lake-s3", "corp-vault", "",
	} {
		if ref, err := s.Parse(text); err == nil {
			t.Errorf("%s: accepted as %s", text, ref)
		}
	}
}

func TestResolve(t *testing.T) {
	v := &vault{url: "https://corp-vault.vault.azure.net", secrets: map[string]string{"lake-s3": "hunter2"},
		disabled: map[string]bool{}}
	s := source(t, v, Options{})
	ref, _ := s.Parse("corp-vault/lake-s3")
	value, version, err := s.Resolve(context.Background(), ref)
	if err != nil || value != "hunter2" || version != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("%q %q %v", value, version, err)
	}
	// every fetch reads the vault (no cache by default): a rotation there is seen at once
	s.Resolve(context.Background(), ref)
	if v.reads.Load() != 2 {
		t.Fatalf("%d reads for 2 fetches", v.reads.Load())
	}
	// the vault down: an error naming the status, never a body
	v.down.Store(true)
	if _, _, err := s.Resolve(context.Background(), ref); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("the vault down: %v", err)
	}
	v.down.Store(false)
	v.disabled["lake-s3"] = true
	if _, _, err := s.Resolve(context.Background(), ref); err == nil {
		t.Fatal("a disabled secret resolves")
	}
	// the allowlist again at the resolution: a reference parsed under a wider one does not resolve
	narrow := NewWithGetter([]Allow{{Vault: "open-vault"}}, func(string) (Getter, error) { return v, nil }, Options{})
	if _, _, err := narrow.Resolve(context.Background(), ref); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("outside the allowlist: %v", err)
	}
}

func TestCache(t *testing.T) {
	v := &vault{url: "https://corp-vault.vault.azure.net", secrets: map[string]string{"lake-s3": "hunter2"}}
	s := source(t, v, Options{CacheTTL: time.Hour})
	ref, _ := s.Parse("corp-vault/lake-s3")
	for range 3 {
		if _, _, err := s.Resolve(context.Background(), ref); err != nil {
			t.Fatal(err)
		}
	}
	if v.reads.Load() != 1 {
		t.Fatalf("%d reads with a cache", v.reads.Load())
	}
}

// a named source (spec 008): its name is the scheme, its errors name its allowlist
func TestNamed(t *testing.T) {
	v := &vault{url: "https://corp-vault.vault.azure.net", secrets: map[string]string{"lake-s3": "hunter2"}, disabled: map[string]bool{}}
	s := source(t, v, Options{}).Named("partner")
	if s.Scheme() != "partner" || s.Kind() != "azkv" {
		t.Fatal(s.Scheme(), s.Kind())
	}
	ref, err := s.Parse("corp-vault/lake-s3")
	if err != nil || ref.String() != "ref+partner://corp-vault/lake-s3" {
		t.Fatalf("%s %v", ref, err)
	}
	if value, _, err := s.Resolve(context.Background(), ref); err != nil || value != "hunter2" {
		t.Fatalf("%q %v", value, err)
	}
	if _, err := s.Parse("evil-vault/lake-s3"); err == nil || !strings.Contains(err.Error(), "material.sources[partner].allow") {
		t.Fatalf("outside: %v", err)
	}
}
