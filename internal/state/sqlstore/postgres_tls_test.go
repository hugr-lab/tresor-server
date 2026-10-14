package sqlstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// cert makes a certificate for names, signed by parent (nil: self-signed, a CA)
func cert(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, names ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	return certWith(t, parent, parentKey, func(*x509.Certificate) {}, names...)
}

// certWith is cert, its template changed by edit
func certWith(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, edit func(*x509.Certificate), names ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: names,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses, tmpl.DNSNames = append(tmpl.IPAddresses, ip), nil
		}
	}
	edit(tmpl)
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
	if err := verifyFQDN([]*x509.Certificate{dotted}, roots, host, time.Time{}); err != nil {
		t.Fatalf("the name with a trailing dot: %v", err)
	}
	if err := verifyFQDN([]*x509.Certificate{plain}, roots, host, time.Time{}); err != nil {
		t.Fatalf("the name as it is: %v", err)
	}
	if err := verifyFQDN([]*x509.Certificate{dotted}, roots, "other.sql.goog", time.Time{}); err == nil {
		t.Fatal("another name passed")
	}
	if err := verifyFQDN([]*x509.Certificate{dotted}, roots, "europe-west1.sql.goog", time.Time{}); err == nil {
		t.Fatal("a parent domain passed")
	}
	other, otherKey := cert(t, nil, nil)
	stranger, _ := cert(t, other, otherKey, host+".")
	if err := verifyFQDN([]*x509.Certificate{stranger}, roots, host, time.Time{}); err == nil {
		t.Fatal("a certificate from another CA passed")
	}
	if err := verifyFQDN(nil, roots, host, time.Time{}); err == nil {
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
	for _, mode := range []string{"require", "verify-ca", "prefer"} {
		other, err := pgx.ParseConfig("host=db.example user=u dbname=d sslmode=" + mode)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range tlsConfigs(other) {
			skip, peer := tc.InsecureSkipVerify, tc.VerifyPeerCertificate != nil
			fqdnTolerant(tc)
			if tc.VerifyConnection != nil || tc.InsecureSkipVerify != skip || (tc.VerifyPeerCertificate != nil) != peer {
				t.Fatalf("%s: changed", mode)
			}
		}
	}
}

// what Go's check refuses, this one refuses too; wildcards and degenerate names match as Go's do
func TestVerifyFQDNRefusals(t *testing.T) {
	ca, caKey := cert(t, nil, nil)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	none := time.Time{}
	client, _ := certWith(t, ca, caKey, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, "db.goog.")
	expired, _ := certWith(t, ca, caKey, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }, "db.goog.")
	wild, _ := cert(t, ca, caKey, "*.b.sql.goog.")
	dots, _ := cert(t, ca, caKey, ".", "*.")
	ip, _ := cert(t, ca, caKey, "10.0.0.5")
	ipAsName, _ := cert(t, ca, caKey, "10.0.0.6.")
	for _, c := range []struct {
		name string
		cert *x509.Certificate
		host string
		ok   bool
	}{
		{"a client's certificate", client, "db.goog", false},
		{"expired", expired, "db.goog", false},
		{"a wildcard, one label", wild, "a.b.sql.goog", true},
		{"a wildcard, two labels", wild, "x.a.b.sql.goog", false},
		{"'.' and '*.'", dots, "db.goog", false},
		{"an IP address", ip, "10.0.0.5", true},
		{"an IP written as a DNS name", ipAsName, "10.0.0.6", false},
	} {
		if err := verifyFQDN([]*x509.Certificate{c.cert}, roots, c.host, none); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// through an intermediate, sent by the server
	mid, midKey := certWith(t, ca, caKey, func(c *x509.Certificate) { c.IsCA, c.BasicConstraintsValid = true, true })
	leaf, _ := cert(t, mid, midKey, "db.goog.")
	if err := verifyFQDN([]*x509.Certificate{leaf, mid}, roots, "db.goog", none); err != nil {
		t.Errorf("through an intermediate: %v", err)
	}
	if err := verifyFQDN([]*x509.Certificate{leaf}, roots, "db.goog", none); err == nil {
		t.Error("an intermediate not sent: passed")
	}
}

// a real handshake: the replaced config verifies through VerifyConnection, each fallback host its own name
func TestFQDNTolerantHandshake(t *testing.T) {
	ca, caKey := cert(t, nil, nil)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf, leafKey := cert(t, ca, caKey, "b.example.")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: leafKey}}})
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
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	cfg, err := pgx.ParseConfig("host=a.example,b.example user=u dbname=d sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	confs := tlsConfigs(cfg)
	if len(confs) != 2 || confs[0].ServerName != "a.example" || confs[1].ServerName != "b.example" {
		t.Fatalf("the hosts' configs: %d", len(confs))
	}
	dial := func(tc *tls.Config) error {
		tc = tc.Clone()
		tc.RootCAs = roots
		fqdnTolerant(tc)
		c, err := (&tls.Dialer{Config: tc}).DialContext(context.Background(), "tcp", ln.Addr().String())
		if err == nil {
			c.Close()
		}
		return err
	}
	if err := dial(confs[1]); err != nil {
		t.Fatalf("b's certificate for b: %v", err)
	}
	if err := dial(confs[0]); err == nil {
		t.Fatal("b's certificate for a: passed")
	}
}
