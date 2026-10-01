// Package azurekeyvault is a KEK in Azure Key Vault or Managed HSM (spec 002): data keys are wrapped and
// unwrapped there (wrapKey/unwrapKey) with the service's identity; the KEK never leaves the vault.
//
// The key is named without a version: new data keys are wrapped under its current version, and each data
// key records the version it was wrapped under (its KEK id: the key's full id and the algorithm), so a
// rotation in the vault makes new data keys and leaves the old ones readable.
package azurekeyvault

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/hugr-lab/tresor-server/internal/keys"
)

const (
	// currentTTL: how long the key's current version is taken as read - a rotation in the vault is seen
	// within it, and a seal does not call the vault.
	currentTTL = time.Minute
	// currentGrace: how long the last version read keeps serving while the vault does not answer. Nothing
	// is weaker for it: a rotation is only seen later.
	currentGrace = time.Hour
)

// Ops are the vault's operations the wrapper uses: azkeys.Client, or a fake in tests.
type Ops interface {
	GetKey(ctx context.Context, name, version string, opts *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
	WrapKey(ctx context.Context, name, version string, p azkeys.KeyOperationParameters, opts *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error)
	UnwrapKey(ctx context.Context, name, version string, p azkeys.KeyOperationParameters, opts *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error)
	Sign(ctx context.Context, name, version string, p azkeys.SignParameters, opts *azkeys.SignOptions) (azkeys.SignResponse, error)
}

// Wrapper wraps under one key of a vault.
type Wrapper struct {
	ops  Ops
	host string // the vault's host, lower case
	name string

	refresh sync.Mutex // one read of the current version at a time, outside mu

	mu        sync.Mutex
	current   string // the current version's KEK id, as Wrap names it
	algorithm azkeys.EncryptionAlgorithm
	readAt    time.Time
}

// ParseKeyURL splits a key URL, https://<vault>/keys/<name>: no version, no port, no query. The host is
// lower-cased: Azure names it so in the ids it returns.
func ParseKeyURL(raw string) (host, name string, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Port() != "" || u.RawQuery != "" ||
		u.Fragment != "" || u.User != nil {
		return "", "", fmt.Errorf("keys.key: an https key URL, https://<vault>/keys/<name>, with no port")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "keys" || parts[1] == "" {
		return "", "", fmt.Errorf("keys.key: https://<vault>/keys/<name>, with no version (new data keys use the current one)")
	}
	return strings.ToLower(u.Hostname()), parts[1], nil
}

// parseKID splits a key id, https://<vault>/keys/<name>/<version>; ok false for anything else.
func parseKID(kid string) (host, name, version string, ok bool) {
	u, err := url.Parse(kid)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Port() != "" || u.RawQuery != "" {
		return "", "", "", false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "keys" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return strings.ToLower(u.Hostname()), parts[1], parts[2], true
}

// New returns a wrapper over a key URL with the service's credential.
func New(keyURL string, cred azcore.TokenCredential) (*Wrapper, error) {
	host, name, err := ParseKeyURL(keyURL)
	if err != nil {
		return nil, err
	}
	client, err := azkeys.NewClient("https://"+host, cred, nil)
	if err != nil {
		return nil, err
	}
	return &Wrapper{ops: client, host: host, name: name}, nil
}

// NewWithOps is New over given operations (tests).
func NewWithOps(keyURL string, ops Ops) (*Wrapper, error) {
	host, name, err := ParseKeyURL(keyURL)
	if err != nil {
		return nil, err
	}
	return &Wrapper{ops: ops, host: host, name: name}, nil
}

// algorithmFor is the wrap algorithm a key's type takes: RSA-OAEP-256 for an RSA key (either service),
// A256KW for an AES key (Managed HSM: oct-HSM only).
func algorithmFor(kty azkeys.KeyType) (azkeys.EncryptionAlgorithm, error) {
	switch kty {
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		return azkeys.EncryptionAlgorithmRSAOAEP256, nil
	case azkeys.KeyTypeOctHSM:
		return azkeys.EncryptionAlgorithmA256KW, nil
	}
	return "", fmt.Errorf("the KEK is a %s key: an RSA key, or an AES key on Managed HSM, wraps data keys", kty)
}

func (w *Wrapper) cached() (string, azkeys.EncryptionAlgorithm, time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.current, w.algorithm, time.Since(w.readAt)
}

// Current is the key's current version (its KEK id), read from the vault at most once a currentTTL; while
// the vault does not answer, the last one read serves for currentGrace.
func (w *Wrapper) Current(ctx context.Context) (string, error) {
	if current, _, age := w.cached(); current != "" && age < currentTTL {
		return current, nil
	}
	w.refresh.Lock()
	defer w.refresh.Unlock()
	current, _, age := w.cached()
	if current != "" && age < currentTTL {
		return current, nil // read meanwhile
	}
	id, alg, err := w.read(ctx)
	if err != nil {
		if current != "" && age < currentGrace {
			return current, nil
		}
		return "", err
	}
	w.mu.Lock()
	w.current, w.algorithm, w.readAt = id, alg, time.Now()
	w.mu.Unlock()
	return id, nil
}

func (w *Wrapper) read(ctx context.Context) (string, azkeys.EncryptionAlgorithm, error) {
	resp, err := w.ops.GetKey(ctx, w.name, "", nil)
	if err != nil {
		return "", "", fmt.Errorf("the KEK %s: %w", w.name, describe(err))
	}
	if resp.Key == nil || resp.Key.KID == nil || resp.Key.Kty == nil {
		return "", "", fmt.Errorf("the KEK %s: the vault named no key id or type", w.name)
	}
	if resp.Attributes != nil && resp.Attributes.Enabled != nil && !*resp.Attributes.Enabled {
		return "", "", fmt.Errorf("the KEK %s is disabled", w.name)
	}
	if _, _, _, ok := w.own(string(*resp.Key.KID)); !ok {
		return "", "", fmt.Errorf("the KEK %s: the vault named a key id that is not this key's", w.name)
	}
	alg, err := algorithmFor(*resp.Key.Kty)
	if err != nil {
		return "", "", err
	}
	return string(*resp.Key.KID) + "#" + string(alg), alg, nil
}

// own splits a key id of this vault's key; ok false for another vault's or key's, or no key id at all.
func (w *Wrapper) own(kid string) (host, name, version string, ok bool) {
	host, name, version, ok = parseKID(kid)
	return host, name, version, ok && host == w.host && strings.EqualFold(name, w.name)
}

func (w *Wrapper) Wrap(ctx context.Context, dek []byte) ([]byte, string, error) {
	current, err := w.Current(ctx)
	if err != nil {
		return nil, "", err
	}
	kid, _, _ := strings.Cut(current, "#")
	_, _, version, _ := w.own(kid)
	_, alg, _ := w.cached()
	resp, err := w.ops.WrapKey(ctx, w.name, version, azkeys.KeyOperationParameters{Algorithm: &alg, Value: dek}, nil)
	if err != nil {
		return nil, "", fmt.Errorf("wrapping under the KEK %s: %w", w.name, describe(err))
	}
	if resp.Result == nil {
		return nil, "", errors.New("the vault answered a wrap with no value")
	}
	return resp.Result, current, nil
}

func (w *Wrapper) Unwrap(ctx context.Context, wrapped []byte, kekID string) ([]byte, error) {
	kid, alg, hasAlg := strings.Cut(kekID, "#")
	_, _, version, ok := w.own(kid)
	switch {
	case !hasAlg || alg == "":
		return nil, fmt.Errorf("%w: a KEK id that is not a vault's (%s)", keys.ErrSealed, kekID)
	case !ok:
		// another vault's or key's: a KEK this service was not given - never sent anywhere
		return nil, fmt.Errorf("%w: the data key was wrapped under another KEK (%s, this one is %s/keys/%s)",
			keys.ErrSealed, kid, w.host, w.name)
	}
	algorithm := azkeys.EncryptionAlgorithm(alg)
	resp, err := w.ops.UnwrapKey(ctx, w.name, version, azkeys.KeyOperationParameters{Algorithm: &algorithm,
		Value: wrapped}, nil)
	if err != nil {
		if bad(err) {
			return nil, fmt.Errorf("%w: the vault does not unwrap the data key: %v", keys.ErrSealed, describe(err))
		}
		return nil, fmt.Errorf("unwrapping under the KEK %s: %w", w.name, describe(err))
	}
	return resp.Result, nil
}

// Root is a secret only the vault can compute (spec 003): an RSA key's deterministic signature (RS256, PKCS#1
// v1.5) of a fixed label - the public key cannot make it; an AES key's deterministic wrap (A256KW) of it. Its
// SHA-256, so it is a key's length. It needs the key's sign (RSA) operation.
func (w *Wrapper) Root(ctx context.Context, kekID string) ([]byte, error) {
	kid, alg, hasAlg := strings.Cut(kekID, "#")
	_, _, version, ok := w.own(kid)
	if !hasAlg || !ok {
		return nil, fmt.Errorf("%w: another KEK's root (%s)", keys.ErrSealed, kekID)
	}
	label := sha256.Sum256([]byte("tresor-server/root/1\x00" + kekID))
	var out []byte
	switch azkeys.EncryptionAlgorithm(alg) {
	case azkeys.EncryptionAlgorithmRSAOAEP256:
		rs256 := azkeys.SignatureAlgorithmRS256
		resp, err := w.ops.Sign(ctx, w.name, version, azkeys.SignParameters{Algorithm: &rs256, Value: label[:]}, nil)
		if err != nil {
			return nil, fmt.Errorf("the KEK %s's root (sign): %w", w.name, describe(err))
		}
		out = resp.Result
	case azkeys.EncryptionAlgorithmA256KW:
		a256 := azkeys.EncryptionAlgorithmA256KW
		resp, err := w.ops.WrapKey(ctx, w.name, version, azkeys.KeyOperationParameters{Algorithm: &a256, Value: label[:]}, nil)
		if err != nil {
			return nil, fmt.Errorf("the KEK %s's root (wrap): %w", w.name, describe(err))
		}
		out = resp.Result
	default:
		return nil, fmt.Errorf("%w: no root for the algorithm %s", keys.ErrSealed, alg)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the KEK %s gave no root", w.name)
	}
	sum := sha256.Sum256(out)
	return sum[:], nil
}

// bad: the vault refused the value itself (a tampered wrap: 400 BadParameter) - not transient, not the
// service's access, not its configuration.
func bad(err error) bool {
	var re *azcore.ResponseError
	return errors.As(err, &re) && re.StatusCode == http.StatusBadRequest && re.ErrorCode == "BadParameter"
}

// describe is a vault or credential error as logged: its status and code, never a request or response
// body.
func describe(err error) error {
	var re *azcore.ResponseError
	if errors.As(err, &re) {
		return fmt.Errorf("the vault answered %d %s", re.StatusCode, re.ErrorCode)
	}
	var auth *azidentity.AuthenticationFailedError
	if errors.As(err, &auth) {
		return errors.New("the service's Azure credential did not get a token (azure.identity)")
	}
	return err
}
