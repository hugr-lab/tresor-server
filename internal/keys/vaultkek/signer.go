package vaultkek

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hugr-lab/tresor-server/internal/vault"
)

// Signer signs digests with a Transit key (spec 007): the exchange's assertion (spec 006's client_auth: vault).
// An RSA key signs RS256 (PKCS#1 v1.5), an ECDSA P-256 key ES256 (JWS: r and s). The private key never leaves
// Vault; an IdP's own key (ZITADEL's) is imported into Transit and its file destroyed.
//
// The version is the latest at start, pinned: the IdP knows one public key, named by the configured kid, so a
// rotation in Transit takes effect at a restart, with the new kid - never before the IdP knows the new key.
type Signer struct {
	vault      Caller
	mount, key string
	alg        string
	version    int
}

// NewSigner reads the key's type and latest version, and signs once: a key that cannot sign (a policy without
// the sign path, a public key imported alone) stops the start.
func NewSigner(ctx context.Context, v Caller, mount, key string) (*Signer, error) {
	if !segment.MatchString(mount) || !segment.MatchString(key) || mount == ".." || key == ".." {
		return nil, errors.New("exchange.key: <mount>/<key>, Transit names")
	}
	name := mount + "/" + key
	var out struct {
		Data struct {
			Type          string `json:"type"`
			LatestVersion int    `json:"latest_version"`
		} `json:"data"`
	}
	if err := v.Do(ctx, http.MethodGet, mount+"/keys/"+key, nil, &out); err != nil {
		var ve *vault.Error
		if errors.As(err, &ve) && ve.Status == http.StatusNotFound {
			return nil, fmt.Errorf("exchange.key %s: no such Transit key", name)
		}
		return nil, fmt.Errorf("exchange.key %s: %w", name, err)
	}
	s := &Signer{vault: v, mount: mount, key: key, version: out.Data.LatestVersion}
	switch out.Data.Type {
	case "rsa-2048", "rsa-3072", "rsa-4096":
		s.alg = "RS256"
	case "ecdsa-p256":
		s.alg = "ES256"
	default:
		return nil, fmt.Errorf("exchange.key %s: a %s key: an RSA or an ECDSA P-256 Transit key signs", name, out.Data.Type)
	}
	if s.version < 1 {
		return nil, fmt.Errorf("exchange.key %s: the Transit key has no version", name)
	}
	probe := sha256.Sum256([]byte("tresor-server/sign-check/1"))
	if _, err := s.Sign(ctx, probe[:]); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Signer) Alg() string { return s.alg }

// Sign signs a SHA-256 digest with the pinned version.
func (s *Signer) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	body := map[string]any{"input": base64.StdEncoding.EncodeToString(digest), "prehashed": true, "key_version": s.version}
	enc := base64.StdEncoding
	if s.alg == "RS256" {
		body["signature_algorithm"] = "pkcs1v15" // Transit's default is PSS: not RS256
	} else {
		body["marshaling_algorithm"] = "jws" // r and s, as JWS wants them (not ASN.1), in base64url
		enc = base64.RawURLEncoding
	}
	var out struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	name := s.mount + "/" + s.key
	if err := s.vault.Do(ctx, http.MethodPost, s.mount+"/sign/"+s.key+"/sha2-256", body, &out); err != nil {
		return nil, fmt.Errorf("exchange.key %s: sign: %w", name, err)
	}
	// vault:v<N>:<signature>
	rest, ok := strings.CutPrefix(out.Data.Signature, fmt.Sprintf("vault:v%d:", s.version))
	if !ok {
		return nil, fmt.Errorf("exchange.key %s: Transit's signature is not of the version asked", name)
	}
	sig, err := enc.DecodeString(rest)
	if err != nil || len(sig) == 0 || (s.alg == "ES256" && len(sig) != 64) {
		return nil, fmt.Errorf("exchange.key %s: Transit's signature does not read", name)
	}
	return sig, nil
}
