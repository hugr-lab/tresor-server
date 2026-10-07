package gcpkms

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
)

// SignOps is the Cloud KMS calls a signer makes: kms.KeyManagementClient, or a fake in tests.
type SignOps interface {
	GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, opts ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}

// Signer signs digests with an asymmetric Cloud KMS key version (spec 012): the exchange's assertion (spec 006's
// client_auth: gcpkms). RSA PKCS#1 v1.5 SHA-256 signs RS256, EC P-256 SHA-256 ES256 (KMS answers ASN.1; the JWS
// wants r and s). The version is configured: the IdP knows one public key, named by the configured kid.
type Signer struct {
	ops     SignOps
	version string
	alg     string
}

// NewSigner reads the version's algorithm, and signs once: a version that cannot sign stops the start.
func NewSigner(ctx context.Context, ops SignOps, version string) (*Signer, error) {
	if !KeyVersion(version) {
		return nil, errors.New("exchange.key: an asymmetric key's version (…/cryptoKeys/<k>/cryptoKeyVersions/<n>)")
	}
	v, err := ops.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: version})
	if err != nil {
		return nil, fmt.Errorf("exchange.key: %w", describe(err, false))
	}
	if v.GetState() != kmspb.CryptoKeyVersion_ENABLED {
		return nil, fmt.Errorf("exchange.key: the version is %s, not enabled", v.GetState())
	}
	s := &Signer{ops: ops, version: version}
	switch v.GetAlgorithm() {
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		s.alg = "RS256"
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		s.alg = "ES256"
	default:
		return nil, fmt.Errorf("exchange.key: a %s version: RSA PKCS#1 SHA-256 or EC P-256 SHA-256 signs", v.GetAlgorithm())
	}
	probe := sha256.Sum256([]byte("tresor-server/sign-check/1"))
	if _, err := s.Sign(ctx, probe[:]); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Signer) Alg() string { return s.alg }

// Sign signs a SHA-256 digest.
func (s *Signer) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	out, err := s.ops.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: s.version,
		Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}}, DigestCrc32C: crc(digest)})
	if err != nil {
		return nil, fmt.Errorf("signing with the KMS key: %w", describe(err, false))
	}
	if !out.GetVerifiedDigestCrc32C() || !sameCRC(out.GetSignatureCrc32C(), out.GetSignature()) || out.GetName() != s.version {
		return nil, errors.New("the KMS answer to an AsymmetricSign failed its checks")
	}
	if s.alg == "RS256" {
		return out.GetSignature(), nil
	}
	var rs struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(out.GetSignature(), &rs); err != nil || len(rest) != 0 || rs.R == nil || rs.S == nil ||
		rs.R.Sign() <= 0 || rs.S.Sign() <= 0 || rs.R.BitLen() > 256 || rs.S.BitLen() > 256 {
		return nil, errors.New("KMS answered an ECDSA signature that does not parse as P-256's")
	}
	jws := make([]byte, 64)
	rs.R.FillBytes(jws[:32])
	rs.S.FillBytes(jws[32:])
	return jws, nil
}
