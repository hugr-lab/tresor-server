// Package azurekeyvault is a KEK in Azure Key Vault or Managed HSM (spec 002): data keys are wrapped and
// unwrapped there (wrapKey/unwrapKey) with the service's identity; the KEK never leaves the vault.
//
// The key is named without a version: new data keys are wrapped under its current version, and each data
// key records the version it was wrapped under (its KEK id is the key's full id), so a rotation in the vault
// makes new data keys and leaves the old ones readable.
package azurekeyvault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/hugr-lab/tresor-server/internal/keys"
)

// currentTTL: how long the key's current version is taken as it was read (a rotation in the vault is seen
// within this time; every seal does not call the vault).
const currentTTL = time.Minute

// Ops are the vault's operations the wrapper uses: azkeys.Client, or a fake in tests.
type Ops interface {
	GetKey(ctx context.Context, name, version string, opts *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
	WrapKey(ctx context.Context, name, version string, p azkeys.KeyOperationParameters, opts *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error)
	UnwrapKey(ctx context.Context, name, version string, p azkeys.KeyOperationParameters, opts *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error)
}

// Wrapper wraps under one key of a vault.
type Wrapper struct {
	ops   Ops
	vault string // https://<vault>.vault.azure.net, as configured
	name  string

	mu        sync.Mutex
	current   string // the current version's KEK id: its full key id and the algorithm, as Wrap names it
	algorithm azkeys.EncryptionAlgorithm
	readAt    time.Time
}

// ParseKeyURL splits a key URL, https://<vault>/keys/<name> - no version, no query.
func ParseKeyURL(raw string) (vault, name string, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("keys.key: an https key URL, https://<vault>/keys/<name>")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "keys" || parts[1] == "" {
		return "", "", fmt.Errorf("keys.key: https://<vault>/keys/<name>, with no version (new data keys use the current one)")
	}
	return "https://" + u.Host, parts[1], nil
}

// New returns a wrapper over a key URL with the service's credential.
func New(keyURL string, cred azcore.TokenCredential) (*Wrapper, error) {
	vault, name, err := ParseKeyURL(keyURL)
	if err != nil {
		return nil, err
	}
	client, err := azkeys.NewClient(vault, cred, nil)
	if err != nil {
		return nil, err
	}
	return &Wrapper{ops: client, vault: vault, name: name}, nil
}

// NewWithOps is New over given operations (tests).
func NewWithOps(keyURL string, ops Ops) (*Wrapper, error) {
	vault, name, err := ParseKeyURL(keyURL)
	if err != nil {
		return nil, err
	}
	return &Wrapper{ops: ops, vault: vault, name: name}, nil
}

// algorithmFor is the wrap algorithm a key's type takes: RSA-OAEP-256 for an RSA key (either service),
// A256KW for an AES key (Managed HSM).
func algorithmFor(kty azkeys.KeyType) (azkeys.EncryptionAlgorithm, error) {
	switch kty {
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		return azkeys.EncryptionAlgorithmRSAOAEP256, nil
	case azkeys.KeyTypeOctHSM, azkeys.KeyTypeOct:
		return azkeys.EncryptionAlgorithmA256KW, nil
	}
	return "", fmt.Errorf("the KEK is a %s key: an RSA key, or an AES key on Managed HSM, wraps data keys", kty)
}

// Current is the key's current version (its full id), read from the vault at most once a currentTTL.
func (w *Wrapper) Current(ctx context.Context) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != "" && time.Since(w.readAt) < currentTTL {
		return w.current, nil
	}
	resp, err := w.ops.GetKey(ctx, w.name, "", nil)
	if err != nil {
		return "", fmt.Errorf("the KEK %s: %w", w.name, describe(err))
	}
	if resp.Key == nil || resp.Key.KID == nil || resp.Key.Kty == nil {
		return "", fmt.Errorf("the KEK %s: the vault named no key id or type", w.name)
	}
	if resp.Attributes != nil && resp.Attributes.Enabled != nil && !*resp.Attributes.Enabled {
		return "", fmt.Errorf("the KEK %s is disabled", w.name)
	}
	alg, err := algorithmFor(*resp.Key.Kty)
	if err != nil {
		return "", err
	}
	w.current, w.algorithm, w.readAt = string(*resp.Key.KID)+"#"+string(alg), alg, time.Now()
	return w.current, nil
}

func (w *Wrapper) Wrap(ctx context.Context, dek []byte) ([]byte, string, error) {
	current, err := w.Current(ctx)
	if err != nil {
		return nil, "", err
	}
	w.mu.Lock()
	alg := w.algorithm
	w.mu.Unlock()
	kid, _, _ := strings.Cut(current, "#")
	id := azkeys.ID(kid)
	resp, err := w.ops.WrapKey(ctx, w.name, id.Version(), azkeys.KeyOperationParameters{Algorithm: &alg, Value: dek}, nil)
	if err != nil {
		return nil, "", fmt.Errorf("wrapping under the KEK %s: %w", w.name, describe(err))
	}
	if resp.KID == nil || resp.Result == nil {
		return nil, "", errors.New("the vault answered a wrap with no key id or value")
	}
	// the algorithm is kept with the id: an unwrap needs it, and the key's type does not change
	return resp.Result, string(*resp.KID) + "#" + string(alg), nil
}

func (w *Wrapper) Unwrap(ctx context.Context, wrapped []byte, kekID string) ([]byte, error) {
	kid, alg, ok := strings.Cut(kekID, "#")
	id := azkeys.ID(kid)
	if !ok || id.Name() == "" || id.Version() == "" {
		return nil, fmt.Errorf("%w: a KEK id that is not this vault's (%s)", keys.ErrSealed, kekID)
	}
	// the data key must be this key's: another vault or key would be a KEK this service was not given
	if !strings.HasPrefix(kid, w.vault+"/keys/"+w.name+"/") || id.Name() != w.name {
		return nil, fmt.Errorf("%w: the data key was wrapped under another KEK (%s, this one is %s/keys/%s)",
			keys.ErrSealed, kid, w.vault, w.name)
	}
	algorithm := azkeys.EncryptionAlgorithm(alg)
	resp, err := w.ops.UnwrapKey(ctx, w.name, id.Version(), azkeys.KeyOperationParameters{Algorithm: &algorithm,
		Value: wrapped}, nil)
	if err != nil {
		if bad(err) {
			return nil, fmt.Errorf("%w: the vault does not unwrap the data key: %v", keys.ErrSealed, describe(err))
		}
		return nil, fmt.Errorf("unwrapping under the KEK %s: %w", w.name, describe(err))
	}
	return resp.Result, nil
}

// bad: the vault refused the value itself (a tampered wrap: 400) - not transient, not the service's access.
func bad(err error) bool {
	var re *azcore.ResponseError
	return errors.As(err, &re) && re.StatusCode == http.StatusBadRequest
}

// describe is a vault error as logged: its status and code, never a request or response body.
func describe(err error) error {
	var re *azcore.ResponseError
	if errors.As(err, &re) {
		return fmt.Errorf("the vault answered %d %s", re.StatusCode, re.ErrorCode)
	}
	return err
}
