// Package vaultkek is the KEK in OpenBao's or HashiCorp Vault's Transit engine (spec 007): data keys wrapped by
// transit/encrypt, unwrapped by transit/decrypt; the root a Transit HMAC at the KEK id's version, which only a
// holder of the right computes. The KEK never leaves Vault.
package vaultkek

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/vault"
)

// Caller is the Vault client: vault.Client, or a fake in tests.
type Caller interface {
	Do(ctx context.Context, method, path string, body, out any) error
}

const (
	currentTTL   = time.Minute // the key's latest version is read at most this often
	currentGrace = time.Hour   // while Vault does not answer, the last one read serves this long
)

var segment = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// Wrapper wraps under one Transit key.
type Wrapper struct {
	vault      Caller
	mount, key string

	mu      sync.Mutex
	current string
	readAt  time.Time
}

// New is a wrapper over mount/key.
func New(v Caller, mount, key string) (*Wrapper, error) {
	if !segment.MatchString(mount) || !segment.MatchString(key) {
		return nil, errors.New("keys: mount and key are Transit names (letters, digits, _ . -)")
	}
	return &Wrapper{vault: v, mount: mount, key: key}, nil
}

// kekID names a version: vault:<mount>/<key>:v<N>.
func (w *Wrapper) kekID(version int) string {
	return fmt.Sprintf("vault:%s/%s:v%d", w.mount, w.key, version)
}

// version reads a KEK id of this key; ok false for another key's, or anything else.
func (w *Wrapper) version(kekID string) (int, bool) {
	rest, ok := strings.CutPrefix(kekID, "vault:"+w.mount+"/"+w.key+":v")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	return n, err == nil && n > 0 && strconv.Itoa(n) == rest
}

// ciphertextVersion is the version a Transit ciphertext names: vault:v<N>:...
func ciphertextVersion(ct string) (int, bool) {
	rest, ok := strings.CutPrefix(ct, "vault:v")
	if !ok {
		return 0, false
	}
	num, _, ok := strings.Cut(rest, ":")
	n, err := strconv.Atoi(num)
	return n, ok && err == nil && n > 0
}

func (w *Wrapper) path(op string) string { return w.mount + "/" + op + "/" + w.key }

func (w *Wrapper) Wrap(ctx context.Context, dek []byte) ([]byte, string, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := w.vault.Do(ctx, http.MethodPost, w.path("encrypt"),
		map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dek)}, &out); err != nil {
		return nil, "", err
	}
	v, ok := ciphertextVersion(out.Data.Ciphertext)
	if !ok {
		return nil, "", errors.New("Transit's ciphertext names no version")
	}
	return []byte(out.Data.Ciphertext), w.kekID(v), nil
}

func (w *Wrapper) Unwrap(ctx context.Context, wrapped []byte, kekID string) ([]byte, error) {
	v, ok := w.version(kekID)
	if !ok {
		return nil, fmt.Errorf("%w: data key wrapped under another KEK (%s)", keys.ErrSealed, kekID)
	}
	if cv, ok := ciphertextVersion(string(wrapped)); !ok || cv != v {
		return nil, fmt.Errorf("%w: a wrapped data key that is not its KEK version's", keys.ErrSealed)
	}
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := w.vault.Do(ctx, http.MethodPost, w.path("decrypt"), map[string]string{"ciphertext": string(wrapped)}, &out); err != nil {
		return nil, sealed(err)
	}
	dek, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: Transit's plaintext does not read", keys.ErrSealed)
	}
	return dek, nil
}

// sealed is ErrSealed for what Transit refuses for good - a ciphertext that does not open, or a version below
// min_decryption_version; anything else (Vault down, permission) is not: no value is known to be bad.
func sealed(err error) error {
	var ve *vault.Error
	if errors.As(err, &ve) && ve.Status == http.StatusBadRequest {
		return fmt.Errorf("%w: %s", keys.ErrSealed, ve.Msg)
	}
	return err
}

// Current is the key's latest version, read at most once a currentTTL; while Vault does not answer, the last
// one read serves for currentGrace.
func (w *Wrapper) Current(ctx context.Context) (string, error) {
	w.mu.Lock()
	current, age := w.current, time.Since(w.readAt)
	w.mu.Unlock()
	if current != "" && age < currentTTL {
		return current, nil
	}
	var out struct {
		Data struct {
			LatestVersion      int  `json:"latest_version"`
			SupportsEncryption bool `json:"supports_encryption"`
			Derived            bool `json:"derived"`
		} `json:"data"`
	}
	if err := w.vault.Do(ctx, http.MethodGet, w.mount+"/keys/"+w.key, nil, &out); err != nil {
		if current != "" && age < currentGrace {
			return current, nil
		}
		return "", err
	}
	if !out.Data.SupportsEncryption || out.Data.Derived || out.Data.LatestVersion < 1 {
		return "", errors.New("the Transit key encrypts with no context: an aes256-gcm96 key, not derived")
	}
	current = w.kekID(out.Data.LatestVersion)
	w.mu.Lock()
	w.current, w.readAt = current, time.Now()
	w.mu.Unlock()
	return current, nil
}

// Root is the KEK version's Transit HMAC of a fixed label (spec 003): deterministic, never exported, computed
// only with the right on the key.
func (w *Wrapper) Root(ctx context.Context, kekID string) ([]byte, error) {
	v, ok := w.version(kekID)
	if !ok {
		return nil, fmt.Errorf("%w: data key wrapped under another KEK (%s)", keys.ErrSealed, kekID)
	}
	label := "tresor-server/root/1\x00" + kekID
	var out struct {
		Data struct {
			HMAC string `json:"hmac"`
		} `json:"data"`
	}
	err := w.vault.Do(ctx, http.MethodPost, w.mount+"/hmac/"+w.key+"/sha2-256",
		map[string]any{"input": base64.StdEncoding.EncodeToString([]byte(label)), "key_version": v}, &out)
	if err != nil {
		return nil, sealed(err)
	}
	mac, ok := strings.CutPrefix(out.Data.HMAC, fmt.Sprintf("vault:v%d:", v))
	if !ok {
		return nil, errors.New("Transit's HMAC is not of the version asked")
	}
	raw, err := base64.StdEncoding.DecodeString(mac)
	if err != nil || len(raw) < 32 {
		return nil, errors.New("Transit's HMAC does not read")
	}
	root := sha256.Sum256(raw)
	return root[:], nil
}

var _ keys.KeyWrapper = (*Wrapper)(nil)
