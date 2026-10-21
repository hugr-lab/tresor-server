package tlsreload

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func pair(t *testing.T, serial int64, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "tresor"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

// write puts a pair where a Secret's volume would: a new ..data directory, swapped in by its symlink
func write(t *testing.T, dir string, n int, certPEM, keyPEM []byte) {
	t.Helper()
	data := filepath.Join(dir, "..data-"+string(rune('a'+n)))
	_ = os.Mkdir(data, 0o700)
	_ = os.WriteFile(filepath.Join(data, "tls.crt"), certPEM, 0o600)
	_ = os.WriteFile(filepath.Join(data, "tls.key"), keyPEM, 0o600)
	link := filepath.Join(dir, "..data")
	tmp := link + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(filepath.Base(data), tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, link); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"tls.crt", "tls.key"} {
		_ = os.Symlink(filepath.Join("..data", f), filepath.Join(dir, f))
	}
}

// the serial a TLS client is served
func served(t *testing.T, addr string) int64 {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the test reads the serial
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

func TestReload(t *testing.T) {
	dir := t.TempDir()
	c1, k1 := pair(t, 1, time.Now().Add(24*time.Hour))
	write(t, dir, 0, c1, k1)
	r, err := New(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: r.GetCertificate})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = c.(*tls.Conn).Handshake(); c.Close() }(c)
		}
	}()
	addr := ln.Addr().String()
	if served(t, addr) != 1 {
		t.Fatal("the first pair")
	}
	// renewed in place: served without a restart
	c2, k2 := pair(t, 2, time.Now().Add(48*time.Hour))
	write(t, dir, 1, c2, k2)
	if changed, err := r.reload(); err != nil || !changed || served(t, addr) != 2 {
		t.Fatalf("renewed: %v %v", changed, err)
	}
	if r.Check(context.Background()) != nil {
		t.Fatal("ready")
	}
	// a key that is not the certificate's: the old pair serves, readiness says so
	_, k3 := pair(t, 3, time.Now().Add(48*time.Hour))
	write(t, dir, 2, c2, k3)
	if _, err := r.reload(); err == nil || served(t, addr) != 2 || r.Check(context.Background()) == nil {
		t.Fatalf("a mismatched pair: %v", err)
	}
	// an expired certificate: refused too
	c4, k4 := pair(t, 4, time.Now().Add(-time.Minute))
	write(t, dir, 3, c4, k4)
	if _, err := r.reload(); err == nil || served(t, addr) != 2 {
		t.Fatalf("an expired pair: %v", err)
	}
	// a good one again: served, and ready again
	c5, k5 := pair(t, 5, time.Now().Add(72*time.Hour))
	write(t, dir, 4, c5, k5)
	if _, err := r.reload(); err != nil || served(t, addr) != 5 || r.Check(context.Background()) != nil {
		t.Fatalf("good again: %v", err)
	}
	// a start with a pair that does not load fails
	if _, err := New(filepath.Join(dir, "nope.crt"), filepath.Join(dir, "tls.key"), slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("a start with no certificate")
	}
}
