package awskms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"

	"github.com/hugr-lab/tresor-server/internal/keys"
)

const (
	keyA = "arn:aws:kms:eu-central-1:123456789012:key/1111aaaa-0000-0000-0000-000000000001"
	keyB = "arn:aws:kms:eu-central-1:123456789012:key/2222bbbb-0000-0000-0000-000000000002"
	mac  = "arn:aws:kms:eu-central-1:123456789012:key/3333cccc-0000-0000-0000-000000000003"
)

// fake is KMS as far as the KEK uses it: a ciphertext names its key and context; Decrypt checks both
type fake struct {
	down bool
	macs int
}

func (f *fake) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if f.down {
		return nil, &smithy.GenericAPIError{Code: "KMSInternalException", Message: "secret-looking detail"}
	}
	blob := append([]byte(aws.ToString(in.KeyId)+"|"+in.EncryptionContext["tresor-server"]+"|"), in.Plaintext...)
	return &kms.EncryptOutput{CiphertextBlob: blob}, nil
}

func (f *fake) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	parts := bytes.SplitN(in.CiphertextBlob, []byte("|"), 3)
	if len(parts) != 3 || string(parts[1]) != in.EncryptionContext["tresor-server"] {
		return nil, &types.InvalidCiphertextException{}
	}
	if string(parts[0]) != aws.ToString(in.KeyId) {
		return nil, &types.IncorrectKeyException{}
	}
	return &kms.DecryptOutput{Plaintext: parts[2]}, nil
}

func (f *fake) GenerateMac(_ context.Context, in *kms.GenerateMacInput, _ ...func(*kms.Options)) (*kms.GenerateMacOutput, error) {
	f.macs++
	m := hmac.New(sha256.New, []byte(aws.ToString(in.KeyId)))
	m.Write(in.Message)
	return &kms.GenerateMacOutput{Mac: m.Sum(nil)}, nil
}

var ctx = context.Background()

func TestWrapUnwrapRoot(t *testing.T) {
	f := &fake{}
	w, err := New(f, keyA, mac)
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{7}, 32)
	wrapped, id, err := w.Wrap(ctx, dek)
	if err != nil || id != "awskms:"+keyA+";mac:"+mac || !w.Owns(id) {
		t.Fatalf("wrap: %s %v", id, err)
	}
	if back, err := w.Unwrap(ctx, wrapped, id); err != nil || !bytes.Equal(back, dek) {
		t.Fatalf("unwrap: %v", err)
	}
	r1, err := w.Root(ctx, id)
	r2, _ := w.Root(ctx, id)
	if err != nil || len(r1) != 32 || !bytes.Equal(r1, r2) {
		t.Fatalf("root: not deterministic, or %v", err)
	}
	// another pair of keys: its own id, its own root; a data key of the other refused as sealed
	other, _ := New(f, keyB, mac)
	otherID, _ := other.Current(ctx)
	if w.Owns(otherID) {
		t.Fatal("owns another pair's id")
	}
	if _, err := w.Unwrap(ctx, wrapped, otherID); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("another KEK id: %v", err)
	}
	if _, err := w.Root(ctx, otherID); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("another root: %v", err)
	}
	if _, err := other.Unwrap(ctx, wrapped, otherID); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("a ciphertext of another key: %v", err)
	}
	// a ciphertext tampered with (its context): sealed, not transient
	bad := append([]byte(nil), wrapped...)
	copy(bad[len(keyA)+1:], "x")
	if _, err := w.Unwrap(ctx, bad, id); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("a tampered ciphertext: %v", err)
	}
	// KMS down: an error naming its code, never its message; not sealed
	f.down = true
	if _, _, err := w.Wrap(ctx, dek); err == nil || errors.Is(err, keys.ErrSealed) || bytes.Contains([]byte(err.Error()), []byte("secret-looking")) {
		t.Fatalf("down: %v", err)
	}
}

func TestNew(t *testing.T) {
	for name, pair := range map[string][2]string{
		"an alias":         {"alias/tresor", mac},
		"a bare key id":    {"1111aaaa-0000-0000-0000-000000000001", mac},
		"one key for both": {keyA, keyA},
		"a mac key alias":  {keyA, "arn:aws:kms:eu-central-1:123456789012:alias/root"},
	} {
		if _, err := New(&fake{}, pair[0], pair[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(&fake{}, "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/abc", mac); err != nil {
		t.Fatalf("a GovCloud ARN: %v", err)
	}
}

// signer is KMS signing with a real ECDSA key (ASN.1 out), and DescribeKey
type signer struct {
	ec    *ecdsa.PrivateKey
	usage types.KeyUsageType
}

func (f *signer) DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return &kms.DescribeKeyOutput{KeyMetadata: &types.KeyMetadata{KeyUsage: f.usage, KeySpec: types.KeySpecEccNistP256}}, nil
}

func (f *signer) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if in.MessageType != types.MessageTypeDigest || in.SigningAlgorithm != types.SigningAlgorithmSpecEcdsaSha256 {
		return nil, &smithy.GenericAPIError{Code: "ValidationException"}
	}
	sig, err := ecdsa.SignASN1(rand.Reader, f.ec, in.Message)
	return &kms.SignOutput{Signature: sig}, err
}

func TestSigner(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, err := NewSigner(ctx, &signer{ec: ec, usage: types.KeyUsageTypeSignVerify}, keyA)
	if err != nil || s.Alg() != "ES256" {
		t.Fatalf("%v %v", s, err)
	}
	digest := sha256.Sum256([]byte("header.payload"))
	sig, err := s.Sign(ctx, digest[:])
	if err != nil || len(sig) != 64 {
		t.Fatalf("sign: %d %v", len(sig), err)
	}
	if !ecdsa.Verify(&ec.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the JWS signature does not verify")
	}
	if _, err := NewSigner(ctx, &signer{ec: ec, usage: types.KeyUsageTypeEncryptDecrypt}, keyA); err == nil {
		t.Fatal("an encryption key signs")
	}
}
