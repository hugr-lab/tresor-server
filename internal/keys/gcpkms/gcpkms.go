// Package gcpkms is a KEK in Cloud KMS (spec 012): two keys - an ENCRYPT_DECRYPT key wraps the data keys (its
// primary version; with additional authenticated data), a MAC key's version gives the root (MacSign), for an
// encryption key does not MAC. A new primary version is a new KEK id: data keys move with rewrap, as Vault's and
// Key Vault's versions. Every request and answer is checked by its CRC32C, as Cloud KMS asks.
package gcpkms

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"regexp"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/hugr-lab/tresor-server/internal/keys"
)

// Ops is the Cloud KMS calls the KEK makes: kms.KeyManagementClient, or a fake in tests.
type Ops interface {
	GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...gax.CallOption) (*kmspb.CryptoKey, error)
	Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error)
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error)
	MacSign(ctx context.Context, req *kmspb.MacSignRequest, opts ...gax.CallOption) (*kmspb.MacSignResponse, error)
}

var (
	cryptoKey  = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]{1,63}/cryptoKeys/[A-Za-z0-9_-]{1,63}$`)
	keyVersion = regexp.MustCompile(`^(projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]{1,63}/cryptoKeys/[A-Za-z0-9_-]{1,63})/cryptoKeyVersions/([1-9][0-9]*)$`)
)

// CryptoKey reports whether s names a crypto key; KeyVersion whether it names one of its versions (configuration).
func CryptoKey(s string) bool  { return cryptoKey.MatchString(s) }
func KeyVersion(s string) bool { return keyVersion.MatchString(s) }

// aad binds a wrapped data key to its purpose: KMS refuses to decrypt it without the same.
var aad = []byte("tresor-server/data-key/1")

// currentTTL: how long the primary version read is used before it is read again; a KMS that does not answer
// leaves the last one in use for currentGrace.
const (
	currentTTL   = time.Minute
	currentGrace = time.Hour
)

// Wrapper wraps data keys under key's primary version, its root from macVersion.
type Wrapper struct {
	ops        Ops
	key        string // projects/…/cryptoKeys/<k>
	macVersion string // projects/…/cryptoKeys/<m>/cryptoKeyVersions/<n>

	mu      sync.Mutex
	current string
	readAt  time.Time
}

// New is a KEK over an encryption key and a MAC key's version.
func New(ops Ops, key, macVersion string) (*Wrapper, error) {
	if !CryptoKey(key) || !KeyVersion(macVersion) {
		return nil, errors.New("keys: key is a crypto key (projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>) and " +
			"mac_key a MAC key's version (…/cryptoKeys/<m>/cryptoKeyVersions/<n>)")
	}
	if strings.HasPrefix(macVersion, key+"/") {
		return nil, errors.New("keys: key and mac_key are two keys - an encryption key does not MAC")
	}
	return &Wrapper{ops: ops, key: key, macVersion: macVersion}, nil
}

func (w *Wrapper) id(version string) string { return "gcpkms:" + version + ";mac:" + w.macVersion }

// Owns: any version of this key, with this MAC version.
func (w *Wrapper) Owns(kekID string) bool {
	_, ok := w.version(kekID)
	return ok
}

// version reads a KEK id of this pair: the encryption key's version; ok false for another's.
func (w *Wrapper) version(kekID string) (string, bool) {
	rest, ok := strings.CutPrefix(kekID, "gcpkms:")
	if !ok {
		return "", false
	}
	version, mac, ok := strings.Cut(rest, ";mac:")
	m := keyVersion.FindStringSubmatch(version)
	if !ok || mac != w.macVersion || m == nil || m[1] != w.key {
		return "", false
	}
	return version, true
}

// Current names the primary version's KEK id, read at most once a minute.
func (w *Wrapper) Current(ctx context.Context) (string, error) {
	w.mu.Lock()
	current, readAt := w.current, w.readAt
	w.mu.Unlock()
	if current != "" && time.Since(readAt) < currentTTL {
		return current, nil
	}
	ck, err := w.ops.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: w.key})
	if err != nil {
		if current != "" && time.Since(readAt) < currentGrace {
			return current, nil // the last one read serves while KMS does not answer
		}
		return "", fmt.Errorf("the KMS key: %w", describe(err, false))
	}
	if ck.GetPrimary() == nil || !strings.HasPrefix(ck.GetPrimary().GetName(), w.key+"/cryptoKeyVersions/") {
		return "", errors.New("the KMS key has no primary version (an ENCRYPT_DECRYPT key has one)")
	}
	current = w.id(ck.GetPrimary().GetName())
	w.mu.Lock()
	w.current, w.readAt = current, time.Now()
	w.mu.Unlock()
	return current, nil
}

func (w *Wrapper) Wrap(ctx context.Context, dek []byte) ([]byte, string, error) {
	out, err := w.ops.Encrypt(ctx, &kmspb.EncryptRequest{Name: w.key, Plaintext: dek, AdditionalAuthenticatedData: aad,
		PlaintextCrc32C: crc(dek), AdditionalAuthenticatedDataCrc32C: crc(aad)})
	if err != nil {
		return nil, "", fmt.Errorf("wrapping under the KMS key: %w", describe(err, false))
	}
	if !out.GetVerifiedPlaintextCrc32C() || !out.GetVerifiedAdditionalAuthenticatedDataCrc32C() ||
		!sameCRC(out.GetCiphertextCrc32C(), out.GetCiphertext()) {
		return nil, "", errors.New("the KMS answer to an Encrypt failed its CRC32C check")
	}
	if !strings.HasPrefix(out.GetName(), w.key+"/cryptoKeyVersions/") {
		return nil, "", errors.New("KMS answered an Encrypt with another key's version")
	}
	id := w.id(out.GetName())
	w.mu.Lock()
	w.current, w.readAt = id, time.Now() // the version KMS wrapped with is the primary now
	w.mu.Unlock()
	return out.GetCiphertext(), id, nil
}

func (w *Wrapper) Unwrap(ctx context.Context, wrapped []byte, kekID string) ([]byte, error) {
	if _, ok := w.version(kekID); !ok {
		return nil, fmt.Errorf("%w: data key wrapped under another KEK (%s)", keys.ErrSealed, kekID)
	}
	// the key, not a version: KMS reads the version from the ciphertext, and refuses one of another key
	out, err := w.ops.Decrypt(ctx, &kmspb.DecryptRequest{Name: w.key, Ciphertext: wrapped, AdditionalAuthenticatedData: aad,
		CiphertextCrc32C: crc(wrapped), AdditionalAuthenticatedDataCrc32C: crc(aad)})
	if err != nil {
		return nil, fmt.Errorf("unwrapping under the KMS key: %w", describe(err, true))
	}
	if !sameCRC(out.GetPlaintextCrc32C(), out.GetPlaintext()) {
		return nil, errors.New("the KMS answer to a Decrypt failed its CRC32C check")
	}
	return out.GetPlaintext(), nil
}

func (w *Wrapper) Root(ctx context.Context, kekID string) ([]byte, error) {
	if _, ok := w.version(kekID); !ok {
		return nil, fmt.Errorf("%w: another KEK's root (%s)", keys.ErrSealed, kekID)
	}
	data := []byte("tresor-server/root/1\x00" + kekID)
	out, err := w.ops.MacSign(ctx, &kmspb.MacSignRequest{Name: w.macVersion, Data: data, DataCrc32C: crc(data)})
	if err != nil {
		return nil, fmt.Errorf("the root from the KMS MAC key: %w", describe(err, false))
	}
	if !out.GetVerifiedDataCrc32C() || !sameCRC(out.GetMacCrc32C(), out.GetMac()) || out.GetName() != w.macVersion {
		return nil, errors.New("the KMS answer to a MacSign failed its checks")
	}
	if len(out.GetMac()) != 32 {
		return nil, errors.New("KMS answered a MacSign with no 32-byte MAC (an HMAC_SHA256 key)")
	}
	return out.GetMac(), nil
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func crc(b []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(b, castagnoli)))
}

func sameCRC(v *wrapperspb.Int64Value, b []byte) bool {
	return v != nil && v.GetValue() == int64(crc32.Checksum(b, castagnoli))
}

// describe is a KMS error: its code, never a message that might quote input; a ciphertext KMS refuses as not
// the key's, or tampered with (decrypting only), is ErrSealed.
func describe(err error, decrypting bool) error {
	code := status.Code(err)
	if decrypting && code == codes.InvalidArgument {
		return fmt.Errorf("%w: KMS refused the ciphertext", keys.ErrSealed)
	}
	if _, ok := status.FromError(err); ok {
		return fmt.Errorf("KMS answered %s", code)
	}
	return err
}
