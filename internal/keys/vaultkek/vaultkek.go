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

var segment = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$`) // not . nor ..

// Wrapper wraps under one Transit key.
type Wrapper struct {
	vault      Caller
	mount, key string

	refresh sync.Mutex // one read of the key at a time

	mu      sync.Mutex
	current string
	latest  int // the current version's number
	readAt  time.Time
}

// New is a wrapper over mount/key.
func New(v Caller, mount, key string) (*Wrapper, error) {
	if !segment.MatchString(mount) || !segment.MatchString(key) || mount == ".." || key == ".." {
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
	// Transit wraps under its latest version: a replica that read an older one learns of the rotation here,
	// rather than making a new data key at every seal until its next read
	w.mu.Lock()
	if v > w.latest {
		w.current, w.latest, w.readAt = w.kekID(v), v, time.Now()
	}
	w.mu.Unlock()
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

// sealedAnswers are what Transit answers, for good, about a value or a version: a ciphertext that does not open,
// a version retired (min_decryption_version) or never made. Anything else - Vault down, a permission, a key
// not found, min_encryption_version - is no verdict on a value: a configuration to fix, or an outage.
var sealedAnswers = []string{
	"message authentication failed", "invalid ciphertext", "unable to decode", "too old", "no such key version",
	"invalid key version", "requested version for hmac", "key version does not exist",
}

func sealed(err error) error {
	var ve *vault.Error
	if !errors.As(err, &ve) || ve.Status != http.StatusBadRequest {
		return err
	}
	msg := strings.ToLower(ve.Msg)
	if strings.Contains(msg, "min_encryption_version") || strings.Contains(msg, "cannot generate hmac") {
		return err // a setting refuses the HMAC (the root) at older versions: not the value's fault
	}
	for _, s := range sealedAnswers {
		if strings.Contains(msg, s) {
			return fmt.Errorf("%w: %s", keys.ErrSealed, ve.Msg)
		}
	}
	return err
}

// Current is the key's latest version, read at most once a currentTTL; while Vault does not answer, the last
// one read serves for currentGrace.
func (w *Wrapper) Current(ctx context.Context) (string, error) {
	cached := func() (string, time.Duration) {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.current, time.Since(w.readAt)
	}
	if current, age := cached(); current != "" && age < currentTTL {
		return current, nil
	}
	w.refresh.Lock()
	defer w.refresh.Unlock()
	current, age := cached()
	if current != "" && age < currentTTL {
		return current, nil // another caller read it meanwhile
	}
	var out struct {
		Data struct {
			Type                 string `json:"type"`
			LatestVersion        int    `json:"latest_version"`
			MinEncryptionVersion int    `json:"min_encryption_version"`
			Derived              bool   `json:"derived"`
			Exportable           bool   `json:"exportable"`
			AllowPlaintextBackup bool   `json:"allow_plaintext_backup"`
		} `json:"data"`
	}
	if err := w.vault.Do(ctx, http.MethodGet, w.mount+"/keys/"+w.key, nil, &out); err != nil {
		if current != "" && age < currentGrace {
			return current, nil
		}
		return "", err
	}
	if err := checkKey(out.Data.Type, out.Data.Derived, out.Data.Exportable, out.Data.AllowPlaintextBackup,
		out.Data.MinEncryptionVersion, out.Data.LatestVersion); err != nil {
		return "", err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if out.Data.LatestVersion >= w.latest {
		w.current, w.latest = w.kekID(out.Data.LatestVersion), out.Data.LatestVersion
	}
	w.readAt = time.Now()
	return w.current, nil
}

// checkKey refuses a Transit key whose root would not be the holder's alone, or not computable: one whose keys
// (the HMAC's with them) can be exported or backed up in plaintext, one derived (no context is given), or one
// whose min_encryption_version refuses the HMAC at older versions.
func checkKey(typ string, derived, exportable, plainBackup bool, minEncryption, latest int) error {
	switch {
	case typ != "aes256-gcm96" && typ != "chacha20-poly1305":
		return fmt.Errorf("the Transit key is a %s key: an aes256-gcm96 (or chacha20-poly1305) key wraps data keys", typ)
	case derived:
		return errors.New("the Transit key is derived: the service gives no context")
	case exportable || plainBackup:
		return errors.New("the Transit key can be exported or backed up in plaintext: its HMAC (the root) would not be Vault's alone")
	case minEncryption > 0:
		return errors.New("the Transit key's min_encryption_version refuses the root's HMAC at older versions: leave it 0, retire versions with min_decryption_version")
	case latest < 1:
		return errors.New("the Transit key has no version")
	}
	return nil
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
