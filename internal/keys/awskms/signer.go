package awskms

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// SignOps is the KMS calls a signer makes: kms.Client, or a fake in tests.
type SignOps interface {
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, opts ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
}

// Signer signs digests with an asymmetric KMS key (spec 012): the exchange's assertion (spec 006's
// client_auth: awskms). An RSA key signs RS256 (PKCS#1 v1.5), an ECC NIST P-256 key ES256 (KMS answers ASN.1;
// the JWS wants r and s). The private key never leaves KMS.
type Signer struct {
	ops SignOps
	key string
	alg string
}

// NewSigner reads the key's spec and usage, and signs once: a key that cannot sign stops the start.
func NewSigner(ctx context.Context, ops SignOps, key string) (*Signer, error) {
	if !KeyARN(key) {
		return nil, errors.New("exchange.key: an asymmetric KMS key's ARN")
	}
	out, err := ops.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(key)})
	if err != nil {
		return nil, fmt.Errorf("exchange.key: %w", describe(err))
	}
	md := out.KeyMetadata
	if md == nil || md.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, errors.New("exchange.key: the KMS key's usage is not SIGN_VERIFY")
	}
	s := &Signer{ops: ops, key: key}
	switch md.KeySpec {
	case types.KeySpecRsa2048, types.KeySpecRsa3072, types.KeySpecRsa4096:
		s.alg = "RS256"
	case types.KeySpecEccNistP256:
		s.alg = "ES256"
	default:
		return nil, fmt.Errorf("exchange.key: a %s key: an RSA or an ECC NIST P-256 KMS key signs", md.KeySpec)
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
	alg := types.SigningAlgorithmSpecRsassaPkcs1V15Sha256
	if s.alg == "ES256" {
		alg = types.SigningAlgorithmSpecEcdsaSha256
	}
	out, err := s.ops.Sign(ctx, &kms.SignInput{KeyId: aws.String(s.key), Message: digest, MessageType: types.MessageTypeDigest,
		SigningAlgorithm: alg})
	if err != nil {
		return nil, fmt.Errorf("signing with the KMS key: %w", describe(err))
	}
	if s.alg == "RS256" {
		return out.Signature, nil
	}
	var rs struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(out.Signature, &rs); err != nil || len(rest) != 0 || rs.R == nil || rs.S == nil {
		return nil, errors.New("KMS answered an ECDSA signature that does not parse")
	}
	jws := make([]byte, 64)
	if rs.R.BitLen() > 256 || rs.S.BitLen() > 256 {
		return nil, errors.New("KMS answered an ECDSA signature out of P-256's range")
	}
	rs.R.FillBytes(jws[:32])
	rs.S.FillBytes(jws[32:])
	return jws, nil
}
