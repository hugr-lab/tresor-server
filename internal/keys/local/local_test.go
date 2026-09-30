package local

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 3394, 4.6: 256 bits of key data with a 256-bit KEK
func TestRFC3394Vector(t *testing.T) {
	kek := unhex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	data := unhex(t, "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
	want := unhex(t, "28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21")
	got, err := wrap(kek, data)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("wrap: %x %v", got, err)
	}
	back, err := unwrap(kek, got)
	if err != nil || !bytes.Equal(back, data) {
		t.Fatalf("unwrap: %x %v", back, err)
	}
	got[3] ^= 1
	if _, err := unwrap(kek, got); err == nil {
		t.Fatal("a tampered wrap unwraps")
	}
}

func TestWrapper(t *testing.T) {
	ctx := context.Background()
	a, _ := New(bytes.Repeat([]byte{1}, 32))
	b, _ := New(bytes.Repeat([]byte{2}, 32))
	dek := bytes.Repeat([]byte{7}, 32)
	wrapped, id, err := a.Wrap(ctx, dek)
	if err != nil || !strings.HasPrefix(id, "local:") {
		t.Fatalf("wrap: %s %v", id, err)
	}
	if back, err := a.Unwrap(ctx, wrapped, id); err != nil || !bytes.Equal(back, dek) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := b.Unwrap(ctx, wrapped, id); err == nil || !strings.Contains(err.Error(), "another KEK") {
		t.Fatalf("another KEK: %v", err)
	}
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("a 16-byte KEK")
	}
	t.Setenv("TRESOR_TEST_KEK_X", "bm90LWJhc2U2NA=!") // not base64
	if _, err := FromEnv("TRESOR_TEST_KEK_X"); err == nil || strings.Contains(err.Error(), "bm90") {
		t.Fatalf("a bad key from the environment: %v", err)
	}
}
