package vaultkek

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Signer signs digests with a Transit key (spec 007): the exchange's assertion (spec 006's client_auth: vault).
// An RSA key signs RS256 (PKCS#1 v1.5), an ECDSA P-256 key ES256 (JWS: r and s). The private key never leaves
// Vault; an IdP's own key (ZITADEL's) is imported into Transit and its file destroyed.
type Signer struct {
	vault      Caller
	mount, key string
	alg        string
}

// NewSigner reads the key's type once: what it signs.
func NewSigner(ctx context.Context, v Caller, mount, key string) (*Signer, error) {
	if !segment.MatchString(mount) || !segment.MatchString(key) {
		return nil, errors.New("exchange.key: <mount>/<key>, Transit names")
	}
	var out struct {
		Data struct {
			Type       string `json:"type"`
			Exportable bool   `json:"exportable"`
		} `json:"data"`
	}
	if err := v.Do(ctx, http.MethodGet, mount+"/keys/"+key, nil, &out); err != nil {
		return nil, fmt.Errorf("exchange.key: %w", err)
	}
	s := &Signer{vault: v, mount: mount, key: key}
	switch out.Data.Type {
	case "rsa-2048", "rsa-3072", "rsa-4096":
		s.alg = "RS256"
	case "ecdsa-p256":
		s.alg = "ES256"
	default:
		return nil, fmt.Errorf("exchange.key: a %s key: an RSA or an ECDSA P-256 Transit key signs", out.Data.Type)
	}
	return s, nil
}

func (s *Signer) Alg() string { return s.alg }

// Sign signs a SHA-256 digest with the key's latest version.
func (s *Signer) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	body := map[string]any{"input": base64.StdEncoding.EncodeToString(digest), "prehashed": true}
	if s.alg == "RS256" {
		body["signature_algorithm"] = "pkcs1v15"
	} else {
		body["marshaling_algorithm"] = "jws" // r and s, as JWS wants them (not ASN.1)
	}
	var out struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := s.vault.Do(ctx, http.MethodPost, s.mount+"/sign/"+s.key+"/sha2-256", body, &out); err != nil {
		return nil, err
	}
	// vault:v<N>:<signature>: base64, or base64url for JWS
	parts := strings.SplitN(out.Data.Signature, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" {
		return nil, errors.New("Transit's signature does not read")
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding} {
		if sig, err := enc.DecodeString(parts[2]); err == nil {
			return sig, nil
		}
	}
	return nil, errors.New("Transit's signature does not read")
}
