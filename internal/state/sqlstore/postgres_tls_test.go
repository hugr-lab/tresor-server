package sqlstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// cert makes a certificate for names, signed by parent (nil: self-signed, a CA)
func cert(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, names ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: names,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if parent == nil {
		tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// Cloud SQL's certificates (a Google-managed CA) name the instance with a trailing dot: verify-full matches it as
// the same name - and nothing else is let through
func TestVerifyFQDN(t *testing.T) {
	ca, caKey := cert(t, nil, nil)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	const host = "ea79.2srw.europe-west1.sql.goog"
	dotted, _ := cert(t, ca, caKey, host+".")
	plain, _ := cert(t, ca, caKey, host)
	if dotted.VerifyHostname(host) == nil {
		t.Fatal("Go's own check matches the dotted name now: fqdnTolerant may go")
	}
	if err := verifyFQDN([]*x509.Certificate{dotted}, roots, host); err != nil {
		t.Fatalf("the name with a trailing dot: %v", err)
	}
	if err := verifyFQDN([]*x509.Certificate{plain}, roots, host); err != nil {
		t.Fatalf("the name as it is: %v", err)
	}
	if err := verifyFQDN([]*x509.Certificate{dotted}, roots, "other.sql.goog"); err == nil {
		t.Fatal("another name passed")
	}
	if err := verifyFQDN([]*x509.Certificate{dotted}, roots, "europe-west1.sql.goog"); err == nil {
		t.Fatal("a parent domain passed")
	}
	other, otherKey := cert(t, nil, nil)
	stranger, _ := cert(t, other, otherKey, host+".")
	if err := verifyFQDN([]*x509.Certificate{stranger}, roots, host); err == nil {
		t.Fatal("a certificate from another CA passed")
	}
	if err := verifyFQDN(nil, roots, host); err == nil {
		t.Fatal("no certificate passed")
	}
}

// verify-full is replaced by the same check, tolerant of the dot; verify-ca and require are left to pgx
func TestFQDNTolerantOnlyVerifyFull(t *testing.T) {
	full, err := pgx.ParseConfig("host=db.example user=u dbname=d sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range tlsConfigs(full) {
		fqdnTolerant(tc)
		if tc.VerifyConnection == nil || !tc.InsecureSkipVerify {
			t.Fatal("verify-full: not replaced")
		}
	}
	ca, err := pgx.ParseConfig("host=db.example user=u dbname=d sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range tlsConfigs(ca) {
		before := tc.VerifyConnection
		fqdnTolerant(tc)
		if (before == nil) != (tc.VerifyConnection == nil) {
			t.Fatal("require: changed")
		}
	}
}
