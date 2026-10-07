// Package awskms is a KEK in AWS KMS (spec 012): two keys - a symmetric encryption key wraps the data keys
// (Encrypt, Decrypt, with an encryption context), an HMAC key gives the root (GenerateMac), for a symmetric
// encryption key does not MAC. KMS rotates the encryption key's material inside the same key, old material still
// decrypting: the KEK id does not change with it, and no rewrap is needed. An HMAC key does not rotate.
package awskms

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"

	"github.com/hugr-lab/tresor-server/internal/keys"
)

// Ops is the KMS calls the KEK makes: kms.Client, or a fake in tests.
type Ops interface {
	Encrypt(ctx context.Context, in *kms.EncryptInput, opts ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, in *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error)
	GenerateMac(ctx context.Context, in *kms.GenerateMacInput, opts ...func(*kms.Options)) (*kms.GenerateMacOutput, error)
}

// keyARN is a KMS key's ARN: an alias or a bare key id would make the KEK id depend on how it was named.
var keyARN = regexp.MustCompile(`^arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:key/[A-Za-z0-9-]+$`)

// KeyARN reports whether s is a KMS key's ARN (configuration).
func KeyARN(s string) bool { return keyARN.MatchString(s) }

// context binds a wrapped data key to its purpose: KMS refuses to decrypt it without the same context.
var context1 = map[string]string{"tresor-server": "data-key/1"}

// Wrapper wraps data keys under key, its root from macKey.
type Wrapper struct {
	ops         Ops
	key, macKey string
	id          string
}

// New is a KEK over two keys' ARNs.
func New(ops Ops, key, macKey string) (*Wrapper, error) {
	if !KeyARN(key) || !KeyARN(macKey) {
		return nil, errors.New("keys: key and mac_key are KMS keys' ARNs (arn:aws:kms:<region>:<account>:key/<id>)")
	}
	if key == macKey {
		return nil, errors.New("keys: key and mac_key are two keys - an encryption key does not MAC")
	}
	return &Wrapper{ops: ops, key: key, macKey: macKey, id: "awskms:" + key + ";mac:" + macKey}, nil
}

func (w *Wrapper) Current(context.Context) (string, error) { return w.id, nil }

// Owns: this pair of keys only.
func (w *Wrapper) Owns(kekID string) bool { return kekID == w.id }

func (w *Wrapper) Wrap(ctx context.Context, dek []byte) ([]byte, string, error) {
	out, err := w.ops.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String(w.key), Plaintext: dek, EncryptionContext: context1})
	if err != nil {
		return nil, "", fmt.Errorf("wrapping under the KMS key: %w", describe(err))
	}
	if len(out.CiphertextBlob) == 0 {
		return nil, "", errors.New("KMS answered an Encrypt with no ciphertext")
	}
	return out.CiphertextBlob, w.id, nil
}

func (w *Wrapper) Unwrap(ctx context.Context, wrapped []byte, kekID string) ([]byte, error) {
	if kekID != w.id {
		return nil, fmt.Errorf("%w: data key wrapped under another KEK (%s)", keys.ErrSealed, kekID)
	}
	// KeyId pinned: a ciphertext of another key in the account is refused, not decrypted with it
	out, err := w.ops.Decrypt(ctx, &kms.DecryptInput{KeyId: aws.String(w.key), CiphertextBlob: wrapped, EncryptionContext: context1})
	if err != nil {
		return nil, fmt.Errorf("unwrapping under the KMS key: %w", describe(err))
	}
	return out.Plaintext, nil
}

func (w *Wrapper) Root(ctx context.Context, kekID string) ([]byte, error) {
	if kekID != w.id {
		return nil, fmt.Errorf("%w: another KEK's root (%s)", keys.ErrSealed, kekID)
	}
	out, err := w.ops.GenerateMac(ctx, &kms.GenerateMacInput{KeyId: aws.String(w.macKey), MacAlgorithm: types.MacAlgorithmSpecHmacSha256,
		Message: []byte("tresor-server/root/1\x00" + kekID)})
	if err != nil {
		return nil, fmt.Errorf("the root from the KMS HMAC key: %w", describe(err))
	}
	if len(out.Mac) != 32 {
		return nil, errors.New("KMS answered a GenerateMac with no 32-byte MAC")
	}
	return out.Mac, nil
}

// describe is a KMS error: its code, never a message that might quote input; a ciphertext KMS refuses as not its
// own, or tampered with, is ErrSealed - nothing transient about it.
func describe(err error) error {
	var invalid *types.InvalidCiphertextException
	var incorrect *types.IncorrectKeyException
	if errors.As(err, &invalid) || errors.As(err, &incorrect) {
		return fmt.Errorf("%w: KMS refused the ciphertext", keys.ErrSealed)
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		return fmt.Errorf("KMS answered %s", api.ErrorCode())
	}
	return err
}
