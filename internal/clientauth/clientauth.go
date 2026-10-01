// Package clientauth makes the service's client assertions for token exchange (spec 006): the service logs in
// to an identity provider with no client secret - a platform identity's token, a projected ServiceAccount
// token, or a JWT it signs (with a key file, or in Key Vault). An assertion is made per request, never cached:
// an IdP may refuse a jti it saw. Nothing here logs a key or an assertion.
package clientauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// Source makes an assertion for a request to tokenURL.
type Source func(ctx context.Context, tokenURL string) (string, error)

// AzureScope is the audience Entra's federated credentials expect of an assertion.
const AzureScope = "api://AzureADTokenExchange/.default"

// Azure is a token of the service's Azure identity (managed or workload) for Entra's federated credential.
func Azure(cred azcore.TokenCredential) Source {
	return func(ctx context.Context, _ string) (string, error) {
		token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{AzureScope}})
		if err != nil {
			return "", errors.New("the service's Azure identity gave no token for the federated credential")
		}
		return token.Token, nil
	}
}

// File is a token read from a file at each request: a projected ServiceAccount token the kubelet rotates.
func File(path string) Source {
	return func(context.Context, string) (string, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("exchange.assertion_file: %w", err)
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return "", errors.New("exchange.assertion_file is empty")
		}
		return token, nil
	}
}

// Signer signs a SHA-256 digest: a local key, or a key in Key Vault.
type Signer interface {
	Alg() string // RS256 or ES256: the JWS alg its signature is
	Sign(ctx context.Context, digest []byte) ([]byte, error)
}

// Audience says what the JWT's aud is: the issuer (ZITADEL, Keycloak), or the token endpoint (Entra).
type Audience struct {
	Issuer        string
	TokenEndpoint bool
}

// Header is what the JWT's header names the key by: kid, and x5t for an IdP that knows a certificate by its
// thumbprint (Entra: the certificate's SHA-1, base64url).
type Header struct {
	KID, X5T string
}

// JWT is a private_key_jwt assertion (RFC 7523): iss and sub the client id, aud the issuer or the token
// endpoint, a fresh jti, a minute (one is made per request: a long one gains nothing, and some IdPs cap it);
// the header names the key as the IdP knows it.
func JWT(clientID string, h Header, aud Audience, signer Signer) Source {
	return func(ctx context.Context, tokenURL string) (string, error) {
		fields := map[string]string{"alg": signer.Alg(), "typ": "JWT"}
		if h.KID != "" {
			fields["kid"] = h.KID
		}
		if h.X5T != "" {
			fields["x5t"] = h.X5T
		}
		header, _ := json.Marshal(fields)
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		now := time.Now()
		audience := aud.Issuer
		if aud.TokenEndpoint {
			audience = tokenURL
		}
		claims, _ := json.Marshal(map[string]any{"iss": clientID, "sub": clientID, "aud": audience,
			"jti": hex.EncodeToString(raw), "iat": now.Unix(), "nbf": now.Add(-30 * time.Second).Unix(),
			"exp": now.Add(time.Minute).Unix()})
		b64 := base64.RawURLEncoding
		signing := b64.EncodeToString(header) + "." + b64.EncodeToString(claims)
		digest := sha256.Sum256([]byte(signing))
		sig, err := signer.Sign(ctx, digest[:])
		if err != nil {
			return "", fmt.Errorf("the assertion was not signed: %w", err)
		}
		return signing + "." + b64.EncodeToString(sig), nil
	}
}

// KeyFile reads a private key for JWT: a ZITADEL key file (JSON: keyId, key, clientId) - its kid and client id
// come with it - or a PEM key (RSA or EC P-256), whose kid is the configuration's.
func KeyFile(path string) (signer Signer, kid, clientID string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", "", fmt.Errorf("exchange.key_file: %w", err)
	}
	var zitadel struct {
		KeyID    string `json:"keyId"`
		Key      string `json:"key"`
		ClientID string `json:"clientId"`
		AppID    string `json:"appId"`
	}
	pemBytes := raw
	if json.Unmarshal(raw, &zitadel) == nil && zitadel.Key != "" {
		pemBytes, kid, clientID = []byte(zitadel.Key), zitadel.KeyID, zitadel.ClientID
	}
	// the first key block: a certificate before it (as Entra's bundles have) is passed over
	var block *pem.Block
	for rest := pemBytes; ; {
		block, rest = pem.Decode(rest)
		if block == nil || strings.HasSuffix(block.Type, "PRIVATE KEY") {
			break
		}
	}
	if block == nil {
		return nil, "", "", errors.New("exchange.key_file: no PEM key in it")
	}
	var key any
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, "", "", errors.New("exchange.key_file: the key does not read") // never the parser's text
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return nil, "", "", errors.New("exchange.key_file: an RSA key of 2048 bits at least")
		}
		return rsaSigner{k}, kid, clientID, nil
	case *ecdsa.PrivateKey:
		if k.Curve.Params().BitSize != 256 {
			return nil, "", "", errors.New("exchange.key_file: an EC key is P-256 (ES256)")
		}
		return ecSigner{k}, kid, clientID, nil
	}
	return nil, "", "", errors.New("exchange.key_file: an RSA or an EC P-256 key")
}

type rsaSigner struct{ key *rsa.PrivateKey }

func (rsaSigner) Alg() string { return "RS256" }

func (s rsaSigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest)
}

type ecSigner struct{ key *ecdsa.PrivateKey }

func (ecSigner) Alg() string { return "ES256" }

// Sign is a JWS ES256 signature: r and s, 32 bytes each (not ASN.1).
func (s ecSigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, digest)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	sv.FillBytes(out[32:])
	return out, nil
}
