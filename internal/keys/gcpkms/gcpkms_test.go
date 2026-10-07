package gcpkms

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
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hugr-lab/tresor-server/internal/keys"
)

const (
	key = "projects/corp-data/locations/europe-west3/keyRings/tresor/cryptoKeys/kek"
	mac = "projects/corp-data/locations/europe-west3/keyRings/tresor/cryptoKeys/root/cryptoKeyVersions/1"
)

// fake is Cloud KMS as far as the KEK uses it: a ciphertext names its version and AAD
type fake struct {
	primary  int
	down     bool
	badCRC   bool
	getCalls int
}

func (f *fake) version() string { return key + "/cryptoKeyVersions/" + string(rune('0'+f.primary)) }

func (f *fake) GetCryptoKey(_ context.Context, _ *kmspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmspb.CryptoKey, error) {
	f.getCalls++
	if f.down {
		return nil, status.Error(codes.Unavailable, "secret-looking detail")
	}
	return &kmspb.CryptoKey{Primary: &kmspb.CryptoKeyVersion{Name: f.version()}}, nil
}

func (f *fake) Encrypt(_ context.Context, r *kmspb.EncryptRequest, _ ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	if f.down {
		return nil, status.Error(codes.Unavailable, "secret-looking detail")
	}
	ct := append([]byte(f.version()+"|"+string(r.AdditionalAuthenticatedData)+"|"), r.Plaintext...)
	out := &kmspb.EncryptResponse{Name: f.version(), Ciphertext: ct, CiphertextCrc32C: crc(ct),
		VerifiedPlaintextCrc32C: sameCRC(r.PlaintextCrc32C, r.Plaintext), VerifiedAdditionalAuthenticatedDataCrc32C: true}
	if f.badCRC {
		out.CiphertextCrc32C = crc([]byte("other"))
	}
	return out, nil
}

func (f *fake) Decrypt(_ context.Context, r *kmspb.DecryptRequest, _ ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	parts := bytes.SplitN(r.Ciphertext, []byte("|"), 3)
	if r.Name != key || len(parts) != 3 || !strings.HasPrefix(string(parts[0]), key+"/") || string(parts[1]) != string(r.AdditionalAuthenticatedData) {
		return nil, status.Error(codes.InvalidArgument, "Decryption failed")
	}
	return &kmspb.DecryptResponse{Plaintext: parts[2], PlaintextCrc32C: crc(parts[2])}, nil
}

func (f *fake) MacSign(_ context.Context, r *kmspb.MacSignRequest, _ ...gax.CallOption) (*kmspb.MacSignResponse, error) {
	m := hmac.New(sha256.New, []byte(r.Name))
	m.Write(r.Data)
	sum := m.Sum(nil)
	return &kmspb.MacSignResponse{Name: r.Name, Mac: sum, MacCrc32C: crc(sum), VerifiedDataCrc32C: sameCRC(r.DataCrc32C, r.Data)}, nil
}

var ctx = context.Background()

func TestWrapUnwrapRoot(t *testing.T) {
	f := &fake{primary: 1}
	w, err := New(f, key, mac)
	if err != nil {
		t.Fatal(err)
	}
	cur, err := w.Current(ctx)
	if err != nil || cur != "gcpkms:"+key+"/cryptoKeyVersions/1;mac:"+mac || !w.Owns(cur) {
		t.Fatalf("current: %s %v", cur, err)
	}
	dek := bytes.Repeat([]byte{9}, 32)
	wrapped, id, err := w.Wrap(ctx, dek)
	if err != nil || id != cur {
		t.Fatalf("wrap: %s %v", id, err)
	}
	if back, err := w.Unwrap(ctx, wrapped, id); err != nil || !bytes.Equal(back, dek) {
		t.Fatalf("unwrap: %v", err)
	}
	r1, err := w.Root(ctx, id)
	r2, _ := w.Root(ctx, id)
	if err != nil || len(r1) != 32 || !bytes.Equal(r1, r2) {
		t.Fatalf("root: %v", err)
	}
	// a new primary: a new id (rewrap moves the data keys); the old id still owned and opened
	f.primary = 2
	_, id2, _ := w.Wrap(ctx, dek)
	if id2 == id || !w.Owns(id) || !w.Owns(id2) {
		t.Fatalf("a new primary: %s %s", id, id2)
	}
	if back, err := w.Unwrap(ctx, wrapped, id); err != nil || !bytes.Equal(back, dek) {
		t.Fatalf("the old version: %v", err)
	}
	if r3, _ := w.Root(ctx, id2); bytes.Equal(r1, r3) {
		t.Fatal("two versions, one root")
	}
	// ids of another pair: not owned, sealed
	for _, other := range []string{
		"gcpkms:" + key + "2/cryptoKeyVersions/1;mac:" + mac,
		"gcpkms:" + key + "/cryptoKeyVersions/1;mac:" + mac + "x",
		"gcpkms:" + key + "/cryptoKeyVersions/01;mac:" + mac,
		"awskms:x", "",
	} {
		if w.Owns(other) {
			t.Errorf("owns %q", other)
		}
		if _, err := w.Unwrap(ctx, wrapped, other); !errors.Is(err, keys.ErrSealed) {
			t.Errorf("unwrap under %q: %v", other, err)
		}
	}
	// a tampered ciphertext: sealed; KMS down: not sealed, no message; a bad CRC: refused
	bad := append([]byte(nil), wrapped...)
	copy(bad[len(key)+20:], "x")
	if _, err := w.Unwrap(ctx, bad, id); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("tampered: %v", err)
	}
	f.down = true
	if _, _, err := w.Wrap(ctx, dek); err == nil || errors.Is(err, keys.ErrSealed) || strings.Contains(err.Error(), "secret-looking") {
		t.Fatalf("down: %v", err)
	}
	if c, err := w.Current(ctx); err != nil || c != id2 {
		t.Fatalf("the last primary serves while KMS is down: %s %v", c, err)
	}
	f.down, f.badCRC = false, true
	if _, _, err := w.Wrap(ctx, dek); err == nil {
		t.Fatal("a bad CRC accepted")
	}
}

func TestNew(t *testing.T) {
	for name, pair := range map[string][2]string{
		"a version as key":      {key + "/cryptoKeyVersions/1", mac},
		"a key as mac":          {key, "projects/corp-data/locations/europe-west3/keyRings/tresor/cryptoKeys/root"},
		"the same key":          {key, key + "/cryptoKeyVersions/1"},
		"a short project":       {"projects/ab/locations/x/keyRings/r/cryptoKeys/k", mac},
		"a path with traversal": {"projects/corp-data/locations/x/keyRings/../cryptoKeys/k", mac},
	} {
		if _, err := New(&fake{}, pair[0], pair[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type signer struct {
	ec  *ecdsa.PrivateKey
	alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
}

func (f *signer) GetCryptoKeyVersion(_ context.Context, r *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
	return &kmspb.CryptoKeyVersion{Name: r.Name, State: kmspb.CryptoKeyVersion_ENABLED, Algorithm: f.alg}, nil
}

func (f *signer) AsymmetricSign(_ context.Context, r *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	d := r.GetDigest().GetSha256()
	sig, err := ecdsa.SignASN1(rand.Reader, f.ec, d)
	return &kmspb.AsymmetricSignResponse{Name: r.Name, Signature: sig, SignatureCrc32C: crc(sig), VerifiedDigestCrc32C: sameCRC(r.DigestCrc32C, d)}, err
}

func TestSigner(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	version := "projects/corp-data/locations/global/keyRings/tresor/cryptoKeys/idp/cryptoKeyVersions/3"
	s, err := NewSigner(ctx, &signer{ec: ec, alg: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256}, version)
	if err != nil || s.Alg() != "ES256" {
		t.Fatalf("%v %v", s, err)
	}
	d := sha256.Sum256([]byte("h.p"))
	sig, err := s.Sign(ctx, d[:])
	if err != nil || !ecdsa.Verify(&ec.PublicKey, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatalf("ES256: %v", err)
	}
	if _, err := NewSigner(ctx, &signer{ec: ec, alg: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION}, version); err == nil {
		t.Fatal("an encryption key signs")
	}
	if _, err := NewSigner(ctx, &signer{ec: ec, alg: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256}, key); err == nil {
		t.Fatal("a key, not a version: accepted")
	}
}
