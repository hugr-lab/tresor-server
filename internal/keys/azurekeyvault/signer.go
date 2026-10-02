package azurekeyvault

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// Signer signs digests with a key in Key Vault (spec 006): the private key never leaves the vault. An RSA key
// signs RS256, an EC P-256 key ES256. It is the KEK's sibling, never the KEK: its own key, its own role (sign).
type Signer struct {
	ops  Ops
	name string
	alg  azkeys.SignatureAlgorithm
}

// NewSigner reads the key's type once, to know its algorithm.
func NewSigner(ctx context.Context, keyURL string, cred azcore.TokenCredential) (*Signer, error) {
	host, name, err := ParseKeyURL(keyURL)
	if err != nil {
		return nil, fmt.Errorf("exchange.key: %w", err)
	}
	client, err := azkeys.NewClient("https://"+host, cred, nil)
	if err != nil {
		return nil, err
	}
	return NewSignerWithOps(ctx, name, client)
}

// NewSignerWithOps is NewSigner over given operations (tests).
func NewSignerWithOps(ctx context.Context, name string, ops Ops) (*Signer, error) {
	resp, err := ops.GetKey(ctx, name, "", nil)
	if err != nil {
		return nil, fmt.Errorf("exchange.key: %w", describe(err))
	}
	s := &Signer{ops: ops, name: name}
	if resp.Key == nil || resp.Key.Kty == nil {
		return nil, fmt.Errorf("exchange.key: the vault named no key type")
	}
	switch *resp.Key.Kty {
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		s.alg = azkeys.SignatureAlgorithmRS256
	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		if resp.Key.Crv == nil || *resp.Key.Crv != azkeys.CurveNameP256 {
			return nil, fmt.Errorf("exchange.key: an EC key is P-256 (ES256)")
		}
		s.alg = azkeys.SignatureAlgorithmES256
	default:
		return nil, fmt.Errorf("exchange.key: an RSA or an EC P-256 key signs, not a %s key", *resp.Key.Kty)
	}
	return s, nil
}

func (s *Signer) Alg() string { return string(s.alg) }

// Sign signs a SHA-256 digest with the key's current version; an ES256 signature comes back as r and s, as
// JWS wants it.
func (s *Signer) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	alg := s.alg
	resp, err := s.ops.Sign(ctx, s.name, "", azkeys.SignParameters{Algorithm: &alg, Value: digest}, nil)
	if err != nil {
		return nil, describe(err)
	}
	return resp.Result, nil
}
