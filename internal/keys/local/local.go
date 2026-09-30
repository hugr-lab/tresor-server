// Package local is a KEK held by the service itself: 32 bytes from a file or an environment variable, for
// development, tests and small installs (spec 002). Data keys are wrapped with AES key wrap (RFC 3394).
package local

import (
	"context"
	"crypto/aes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Wrapper wraps under one local key. Its id is a fingerprint of the key, so a data key wrapped under
// another local key says so instead of failing to unwrap blind.
type Wrapper struct {
	kek []byte
	id  string
}

// New returns a wrapper over a 32-byte key.
func New(kek []byte) (*Wrapper, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("a local KEK is 32 bytes, not %d", len(kek))
	}
	sum := sha256.Sum256(append([]byte("tresor-server/kek-id/1\x00"), kek...))
	return &Wrapper{kek: append([]byte(nil), kek...), id: "local:" + hex.EncodeToString(sum[:8])}, nil
}

// FromEnv reads a base64 key from an environment variable; FromFile from a file. Errors name where, never
// what.
func FromEnv(name string) (*Wrapper, error) {
	value := os.Getenv(name)
	if value == "" {
		return nil, fmt.Errorf("the local KEK: %s is empty (32 bytes, base64)", name)
	}
	return decode(value, name)
}

func FromFile(path string) (*Wrapper, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the local KEK: %w", err)
	}
	return decode(strings.TrimSpace(string(data)), path)
}

func decode(value, from string) (*Wrapper, error) {
	kek, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("the local KEK in %s is not base64", from)
	}
	w, err := New(kek)
	if err != nil {
		return nil, fmt.Errorf("the local KEK in %s: %w", from, err)
	}
	return w, nil
}

func (w *Wrapper) Current(context.Context) (string, error) { return w.id, nil }

func (w *Wrapper) Wrap(_ context.Context, dek []byte) ([]byte, string, error) {
	out, err := wrap(w.kek, dek)
	return out, w.id, err
}

func (w *Wrapper) Unwrap(_ context.Context, wrapped []byte, kekID string) ([]byte, error) {
	if kekID != w.id {
		return nil, fmt.Errorf("the data key was wrapped under another KEK (%s, this one is %s)", kekID, w.id)
	}
	return unwrap(w.kek, wrapped)
}

// defaultIV is RFC 3394's initial value.
var defaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

var errUnwrap = errors.New("the data key does not unwrap under this KEK")

// wrap is RFC 3394 AES key wrap (2.2.1).
func wrap(kek, plain []byte) ([]byte, error) {
	if len(plain)%8 != 0 || len(plain) < 16 {
		return nil, errors.New("key wrap needs a multiple of 8 bytes, 16 or more")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(plain) / 8
	a := append([]byte(nil), defaultIV...)
	r := make([][]byte, n)
	for i := range n {
		r[i] = append([]byte(nil), plain[i*8:(i+1)*8]...)
	}
	b := make([]byte, 16)
	for j := range 6 {
		for i := range n {
			copy(b, a)
			copy(b[8:], r[i])
			block.Encrypt(b, b)
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(b[:8])^t)
			copy(r[i], b[8:])
		}
	}
	out := append([]byte(nil), a...)
	for i := range n {
		out = append(out, r[i]...)
	}
	return out, nil
}

// unwrap is RFC 3394 AES key unwrap (2.2.2), with the integrity check.
func unwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped)%8 != 0 || len(wrapped) < 24 {
		return nil, errUnwrap
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(wrapped)/8 - 1
	a := append([]byte(nil), wrapped[:8]...)
	r := make([][]byte, n)
	for i := range n {
		r[i] = append([]byte(nil), wrapped[(i+1)*8:(i+2)*8]...)
	}
	b := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(b, binary.BigEndian.Uint64(a)^t)
			copy(b[8:], r[i])
			block.Decrypt(b, b)
			copy(a, b[:8])
			copy(r[i], b[8:])
		}
	}
	if subtle.ConstantTimeCompare(a, defaultIV) != 1 {
		return nil, errUnwrap
	}
	out := make([]byte, 0, n*8)
	for i := range n {
		out = append(out, r[i]...)
	}
	return out, nil
}
