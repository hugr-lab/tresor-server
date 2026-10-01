package azurekeyvault

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/hugr-lab/tresor-server/internal/keys"
)

// vault is a Key Vault with one RSA key and its versions: RSA-OAEP-256 as the service does it.
type vault struct {
	mu       sync.Mutex
	url      string
	name     string
	versions map[string]*rsa.PrivateKey
	current  string
	disabled bool
	failing  bool
	calls    int
}

func newVault(t *testing.T) *vault {
	v := &vault{url: "https://corp-kv.vault.azure.net", name: "tresor-kek", versions: map[string]*rsa.PrivateKey{}}
	v.rotate(t)
	return v
}

func (v *vault) rotate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.current = fmt.Sprintf("%032x", len(v.versions)+1)
	v.versions[v.current] = key
}

func (v *vault) kid(version string) *azkeys.ID {
	id := azkeys.ID(v.url + "/keys/" + v.name + "/" + version)
	return &id
}

func (v *vault) GetKey(_ context.Context, name, version string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	if v.failing {
		return azkeys.GetKeyResponse{}, &azcore.ResponseError{StatusCode: 503, ErrorCode: "ServiceUnavailable"}
	}
	if name != v.name {
		return azkeys.GetKeyResponse{}, &azcore.ResponseError{StatusCode: 404, ErrorCode: "KeyNotFound"}
	}
	kty, enabled := azkeys.KeyTypeRSA, !v.disabled
	return azkeys.GetKeyResponse{KeyBundle: azkeys.KeyBundle{Key: &azkeys.JSONWebKey{KID: v.kid(v.current), Kty: &kty},
		Attributes: &azkeys.KeyAttributes{Enabled: &enabled}}}, nil
}

func (v *vault) WrapKey(_ context.Context, name, version string, p azkeys.KeyOperationParameters, _ *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	v.mu.Lock()
	key := v.versions[version]
	v.mu.Unlock()
	if key == nil || *p.Algorithm != azkeys.EncryptionAlgorithmRSAOAEP256 {
		return azkeys.WrapKeyResponse{}, &azcore.ResponseError{StatusCode: 400, ErrorCode: "BadParameter"}
	}
	out, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, p.Value, nil)
	if err != nil {
		return azkeys.WrapKeyResponse{}, err
	}
	return azkeys.WrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{KID: v.kid(version), Result: out}}, nil
}

func (v *vault) Sign(_ context.Context, name, version string, p azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
	v.mu.Lock()
	if version == "" { // the current one, as Key Vault takes it
		version = v.current
	}
	key := v.versions[version]
	v.mu.Unlock()
	if key == nil || *p.Algorithm != azkeys.SignatureAlgorithmRS256 {
		return azkeys.SignResponse{}, &azcore.ResponseError{StatusCode: 400, ErrorCode: "BadParameter"}
	}
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, p.Value) // deterministic, as the vault's RS256
	if err != nil {
		return azkeys.SignResponse{}, err
	}
	return azkeys.SignResponse{KeyOperationResult: azkeys.KeyOperationResult{KID: v.kid(version), Result: sig}}, nil
}

func (v *vault) UnwrapKey(_ context.Context, name, version string, p azkeys.KeyOperationParameters, _ *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	v.mu.Lock()
	key := v.versions[version]
	v.mu.Unlock()
	if key == nil {
		return azkeys.UnwrapKeyResponse{}, &azcore.ResponseError{StatusCode: 404, ErrorCode: "KeyNotFound"}
	}
	out, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, p.Value, nil)
	if err != nil {
		return azkeys.UnwrapKeyResponse{}, &azcore.ResponseError{StatusCode: 400, ErrorCode: "BadParameter"}
	}
	return azkeys.UnwrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{KID: v.kid(version), Result: out}}, nil
}

var ctx = context.Background()

func TestParseKeyURL(t *testing.T) {
	if v, n, err := ParseKeyURL("https://Corp-KV.vault.azure.net/keys/tresor-kek"); err != nil || v != "corp-kv.vault.azure.net" || n != "tresor-kek" {
		t.Fatalf("%s %s %v", v, n, err)
	}
	for _, bad := range []string{"http://corp-kv.vault.azure.net/keys/k", "https://corp-kv.vault.azure.net/keys/k/0123",
		"https://corp-kv.vault.azure.net/secrets/k", "https://corp-kv.vault.azure.net/keys/k?x=1", "corp-kv/keys/k",
		"https://corp-kv.vault.azure.net:443/keys/k"} {
		if _, _, err := ParseKeyURL(bad); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

func TestWrapUnwrap(t *testing.T) {
	v := newVault(t)
	w, err := NewWithOps(v.url+"/keys/"+v.name, v)
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{7}, 32)
	wrapped, kekID, err := w.Wrap(ctx, dek)
	if err != nil {
		t.Fatal(err)
	}
	if want := string(*v.kid(v.current)) + "#RSA-OAEP-256"; kekID != want {
		t.Fatalf("the KEK id names the version and the algorithm: %s", kekID)
	}
	if back, err := w.Unwrap(ctx, wrapped, kekID); err != nil || !bytes.Equal(back, dek) {
		t.Fatalf("unwrap: %v", err)
	}
	// the operator's spelling of the vault does not matter: Azure names it in lower case
	upper, _ := NewWithOps("https://CORP-KV.vault.azure.net/keys/TRESOR-KEK", v)
	if back, err := upper.Unwrap(ctx, wrapped, kekID); err != nil || !bytes.Equal(back, dek) {
		t.Fatalf("a vault URL in capitals: %v", err)
	}
	// a tampered wrap: the vault refuses the value - ErrSealed, not an outage
	wrapped[10] ^= 1
	if _, err := w.Unwrap(ctx, wrapped, kekID); !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("a tampered wrap: %v", err)
	}
	// a data key of another vault or key is never sent anywhere
	for _, other := range []string{"https://evil.vault.azure.net/keys/tresor-kek/01#RSA-OAEP-256",
		v.url + "/keys/other/01#RSA-OAEP-256", "local:0123",
		// malformed ids: never a panic (azkeys.ID would dereference nil), always ErrSealed
		"local:abc#x", "%zz#x", "https://v.vault.azure.net#A", "local#x", v.url + "/keys/tresor-kek#RSA-OAEP-256",
		v.url + "/keys/tresor-kek/01/extra#RSA-OAEP-256", ""} {
		if _, err := w.Unwrap(ctx, wrapped, other); !errors.Is(err, keys.ErrSealed) {
			t.Errorf("%s: %v", other, err)
		}
	}
}

// a new version in the vault: new data keys, and the old ones still open (their version is recorded)
func TestRotationInTheVault(t *testing.T) {
	v := newVault(t)
	w, _ := NewWithOps(v.url+"/keys/"+v.name, v)
	store := &dataKeys{keys: map[string]keys.DataKey{}}
	e := keys.NewEnvelope(w, store, keys.Options{})
	first, sealed, err := e.Seal(ctx, []byte("aad"), []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	v.rotate(t)
	w.readAt = time.Time{} // past the current version's TTL
	second, _, err := e.Seal(ctx, []byte("aad"), []byte("x"))
	if err != nil || second == first {
		t.Fatalf("a new KEK version makes a new data key: %s %v", second, err)
	}
	other := keys.NewEnvelope(w, store, keys.Options{}) // another replica, no cache
	if plain, err := other.Open(ctx, first, []byte("aad"), sealed); err != nil || string(plain) != "hunter2" {
		t.Fatalf("a value under the old version: %v", err)
	}
	// the current version is read at most once a minute, and one data key serves every seal
	calls, keysBefore := v.calls, len(store.keys)
	for range 5 {
		if id, _, err := e.Seal(ctx, nil, []byte("x")); err != nil || id != second {
			t.Fatalf("a seal under another data key: %s %v", id, err)
		}
	}
	if v.calls != calls || len(store.keys) != keysBefore {
		t.Fatalf("%d vault reads, %d new data keys for 5 seals", v.calls-calls, len(store.keys)-keysBefore)
	}
	// the vault does not answer: the last version read keeps serving (a rotation is only seen later)
	v.failing = true
	w.readAt = time.Now().Add(-2 * time.Minute)
	if _, _, err := e.Seal(ctx, nil, []byte("x")); err != nil {
		t.Fatalf("a vault blip fails a seal that needs no vault: %v", err)
	}
	// ... for an hour at most
	w.readAt = time.Now().Add(-2 * time.Hour)
	if _, _, err := e.Seal(ctx, nil, []byte("x")); err == nil {
		t.Fatal("a version read two hours ago still serves")
	}
	v.failing = false
	// a disabled key: nothing new is sealed
	v.disabled = true
	w.readAt = time.Time{}
	if _, _, err := e.Seal(ctx, nil, []byte("x")); err == nil {
		t.Fatal("sealed under a disabled KEK")
	}
}

type dataKeys struct {
	mu     sync.Mutex
	keys   map[string]keys.DataKey
	active string
	slot   int64
}

func (s *dataKeys) Get(_ context.Context, id string) (keys.DataKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dk, ok := s.keys[id]
	if !ok {
		return keys.DataKey{}, keys.ErrNoDataKey
	}
	return dk, nil
}

func (s *dataKeys) Active(ctx context.Context) (keys.DataKey, int64, error) {
	s.mu.Lock()
	id, slot := s.active, s.slot
	s.mu.Unlock()
	if id == "" {
		return keys.DataKey{}, 0, keys.ErrNoDataKey
	}
	dk, err := s.Get(ctx, id)
	return dk, slot, err
}

func (s *dataKeys) Activate(_ context.Context, dk keys.DataKey, slot int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slot != s.slot {
		return keys.ErrKeyRace
	}
	s.keys[dk.ID], s.active, s.slot = dk, dk.ID, s.slot+1
	return nil
}

func (s *dataKeys) List(context.Context) ([]keys.DataKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []keys.DataKey
	for _, dk := range s.keys {
		out = append(out, dk)
	}
	return out, nil
}

func (s *dataKeys) Rewrapped(_ context.Context, id, from string, wrapped []byte, kekID string, tag []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dk, ok := s.keys[id]
	if !ok || dk.KEKID != from {
		return false, nil
	}
	dk.Wrapped, dk.KEKID, dk.Tag = wrapped, kekID, tag
	s.keys[id] = dk
	return true, nil
}

// after a rotation, rewrap moves every data key to the current version: the old version can be retired, and
// what was sealed before still opens - no value is re-encrypted
func TestRewrap(t *testing.T) {
	v := newVault(t)
	w, _ := NewWithOps(v.url+"/keys/"+v.name, v)
	store := &dataKeys{keys: map[string]keys.DataKey{}}
	e := keys.NewEnvelope(w, store, keys.Options{})
	id, sealed, err := e.Seal(ctx, []byte("aad"), []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	old := v.current
	v.rotate(t)
	w.readAt = time.Time{}
	if n, err := e.Rewrap(ctx, false, nil); err != nil || n != 1 {
		t.Fatalf("rewrap: %d %v", n, err)
	}
	if n, _ := e.Rewrap(ctx, false, nil); n != 0 {
		t.Fatalf("a second rewrap: %d", n)
	}
	v.mu.Lock()
	delete(v.versions, old) // retired in the vault
	v.mu.Unlock()
	fresh := keys.NewEnvelope(w, store, keys.Options{})
	if plain, err := fresh.Open(ctx, id, []byte("aad"), sealed); err != nil || string(plain) != "hunter2" {
		t.Fatalf("after the old version is gone: %v", err)
	}
}

// rewrap goes on past a data key it cannot rewrap, and names it: the others still move
func TestRewrapSkips(t *testing.T) {
	v := newVault(t)
	w, _ := NewWithOps(v.url+"/keys/"+v.name, v)
	store := &dataKeys{keys: map[string]keys.DataKey{}}
	e := keys.NewEnvelope(w, store, keys.Options{})
	if _, _, err := e.Seal(ctx, nil, []byte("x")); err != nil {
		t.Fatal(err)
	}
	store.keys["foreign"] = keys.DataKey{ID: "foreign", KEKID: "local:0123", Wrapped: []byte("w")}
	v.rotate(t)
	w.readAt = time.Time{}
	n, err := e.Rewrap(ctx, false, nil)
	if n != 1 || err == nil || !strings.Contains(err.Error(), "foreign") {
		t.Fatalf("rewrap past a foreign data key: %d %v", n, err)
	}
}

// an RSA KEK wraps with its public key: whoever could write the store could plant a data key that unwraps, and
// seal material of their choice under it. Its tag, under a root only the vault computes, gives it away
func TestPlantedDataKey(t *testing.T) {
	v := newVault(t)
	w, _ := NewWithOps(v.url+"/keys/"+v.name, v)
	store := &dataKeys{keys: map[string]keys.DataKey{}}
	e := keys.NewEnvelope(w, store, keys.Options{})
	if _, _, err := e.Seal(ctx, nil, []byte("x")); err != nil {
		t.Fatal(err)
	}
	// the attacker: the public key, a data key of their own, a tag they cannot compute
	mine := bytes.Repeat([]byte{9}, 32)
	v.mu.Lock()
	pub := v.versions[v.current].PublicKey
	kid := string(*v.kid(v.current)) + "#RSA-OAEP-256"
	v.mu.Unlock()
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &pub, mine, nil)
	if err != nil {
		t.Fatal(err)
	}
	// a value the attacker seals under their own data key, as the store would hold it: nonce, then ciphertext
	block, _ := aes.NewCipher(mine)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	sealed := gcm.Seal(nonce, nonce, []byte("the attacker's material"), []byte("aad"))
	for name, tag := range map[string][]byte{"a forged tag": bytes.Repeat([]byte{1}, 32), "no tag": nil} {
		store.keys["planted"] = keys.DataKey{ID: "planted", KEKID: kid, Wrapped: wrapped, Tag: tag}
		fresh := keys.NewEnvelope(w, store, keys.Options{})
		if plain, err := fresh.Open(ctx, "planted", []byte("aad"), sealed); !errors.Is(err, keys.ErrSealed) {
			t.Errorf("%s: opened %q, %v", name, plain, err)
		}
	}
	// rewrap tags a data key with none - the operator vouches for the store as it is - and never one whose
	// tag does not match
	store.keys["planted"] = keys.DataKey{ID: "planted", KEKID: kid, Wrapped: wrapped, Tag: bytes.Repeat([]byte{1}, 32)}
	if _, err := e.Rewrap(ctx, false, nil); err == nil || !strings.Contains(err.Error(), "planted") {
		t.Fatalf("rewrap over a forged tag: %v", err)
	}
	delete(store.keys, "planted")
	// a data key with no tag: a routine rewrap (after a rotation) skips and names it - one planted since would
	// carry none either; only --tag-untagged tags it, naming each
	store.keys["legacy"] = keys.DataKey{ID: "legacy", KEKID: kid, Wrapped: wrapped}
	if n, err := e.Rewrap(ctx, false, nil); n != 0 || err == nil || !strings.Contains(err.Error(), "legacy") ||
		len(store.keys["legacy"].Tag) != 0 {
		t.Fatalf("a routine rewrap over a key with no tag: %d %v", n, err)
	}
	var named []string
	if n, err := e.Rewrap(ctx, true, func(id string) { named = append(named, id) }); n != 1 || err != nil ||
		len(store.keys["legacy"].Tag) == 0 || len(named) != 1 || named[0] != "legacy" {
		t.Fatalf("rewrap --tag-untagged: %d %v %v", n, err, named)
	}
}

// the exchange's signer (spec 006): RS256 with the key's current version, in the vault
func TestSigner(t *testing.T) {
	v := newVault(t)
	s, err := NewSignerWithOps(context.Background(), "tresor-kek", v)
	if err != nil || s.Alg() != "RS256" {
		t.Fatalf("%v %v", s, err)
	}
	digest := sha256.Sum256([]byte("header.claims"))
	sig, err := s.Sign(context.Background(), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&v.versions[v.current].PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("the signature: %v", err)
	}
	if _, err := NewSignerWithOps(context.Background(), "other", v); err == nil {
		t.Fatal("a key the vault has not")
	}
}
