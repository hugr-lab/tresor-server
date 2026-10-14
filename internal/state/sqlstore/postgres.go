package sqlstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hugr-lab/tresor-server/internal/config"
	"github.com/hugr-lab/tresor-server/internal/keys"
)

var sslModeKey = regexp.MustCompile(`(?i)(?:^|\s)sslmode\s*=\s*'?([a-z-]+)`)

// sslMode is a DSN's sslmode, "" when it names none (pgx then prefers TLS and falls back to plain text).
func sslMode(dsn string) string {
	if u, err := url.Parse(dsn); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Query().Get("sslmode")
	}
	if m := sslModeKey.FindStringSubmatch(dsn); m != nil {
		return m[1]
	}
	return ""
}

// OpenPostgres opens a PostgreSQL database (spec 002): several replicas. The DSN names the server, the
// database and the user, never a password: login gives it, for each new connection - an Entra token on
// Azure Database for PostgreSQL.
func OpenPostgres(ctx context.Context, dsn string, login Login, maxOpen int, wrapper keys.KeyWrapper, opts Options) (*Store, error) {
	if dsnHasPassword(dsn) {
		return nil, errors.New("state.dsn: a DSN carries no password - it comes from state.auth")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("state.dsn: not a PostgreSQL DSN") // its text may hold what it should not
	}
	// the password - an Entra token - goes over this connection: off this machine, only over TLS with the
	// server's certificate checked (pgx's default, prefer, falls back to plain text; require checks nothing)
	if sslMode(dsn) != "verify-full" {
		// every host the DSN names: pgx falls back to the next one, and the token goes with it
		for _, host := range hostsOf(cfg) {
			if !config.IsLoopback(host) {
				return nil, errors.New("state.dsn: sslmode=verify-full is required for a server off this machine")
			}
		}
	}
	for _, tc := range tlsConfigs(cfg) {
		fqdnTolerant(tc)
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	db := stdlib.OpenDB(*cfg, stdlib.OptionBeforeConnect(func(ctx context.Context, cc *pgx.ConnConfig) error {
		pw, err := login.Password(ctx)
		if err != nil {
			return err
		}
		cc.Password = pw
		return nil
	}))
	if maxOpen <= 0 {
		maxOpen = 10 // a small server (Burstable B1ms) has few connections to give
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxOpen)
	db.SetConnMaxLifetime(30 * time.Minute) // a connection's token expires; a new one logs in afresh
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("state: the PostgreSQL database: %w", err)
	}
	s, err := open(ctx, db, Postgres, wrapper, opts)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("state: %w", err)
	}
	return s, nil
}

// tlsConfigs are the TLS configurations a connection may use: the DSN's, and its fallbacks'.
func tlsConfigs(cfg *pgx.ConnConfig) []*tls.Config {
	out := []*tls.Config{}
	if cfg.TLSConfig != nil {
		out = append(out, cfg.TLSConfig)
	}
	for _, f := range cfg.Fallbacks {
		if f.TLSConfig != nil && f.TLSConfig != cfg.TLSConfig {
			out = append(out, f.TLSConfig)
		}
	}
	return out
}

// fqdnTolerant verifies a verify-full connection as Go does, but matches the server's name to a certificate's DNS
// name written as an absolute one, with a trailing dot: Cloud SQL's certificates from a Google-managed CA name the
// instance so ("….sql.goog."), which Go's own hostname check never matches. The chain is checked against the same
// roots; only the dot is set aside - the same name, not a looser one.
//
// pgx builds verify-full as a config that verifies (InsecureSkipVerify false) and names the host; every other mode
// skips Go's check and verifies its own way, or not at all - left as it is. Should pgx change that, nothing is
// replaced: Go's own check stays, failing closed on the dotted name.
func fqdnTolerant(tc *tls.Config) {
	if tc.InsecureSkipVerify || tc.ServerName == "" || tc.VerifyConnection != nil {
		return // not verify-full, or verified already
	}
	name, roots, now := tc.ServerName, tc.RootCAs, tc.Time
	tc.InsecureSkipVerify = true // replaced by VerifyConnection below, which checks the chain and the name
	tc.VerifyConnection = func(cs tls.ConnectionState) error {
		at := time.Time{}
		if now != nil {
			at = now()
		}
		return verifyFQDN(cs.PeerCertificates, roots, name, at)
	}
}

// hostsOf are the hosts a DSN names: the first, and its fallbacks'.
func hostsOf(cfg *pgx.ConnConfig) []string {
	hosts := []string{cfg.Host}
	for _, f := range cfg.Fallbacks {
		hosts = append(hosts, f.Host)
	}
	return hosts
}

// verifyFQDN checks a server's chain against roots (nil: the system's), and that its leaf names name - a DNS name
// with a trailing dot counting as the same name.
func verifyFQDN(certs []*x509.Certificate, roots *x509.CertPool, name string, at time.Time) error {
	if len(certs) == 0 {
		return errors.New("tls: the server sent no certificate")
	}
	opts := x509.VerifyOptions{Roots: roots, Intermediates: x509.NewCertPool(), CurrentTime: at} // server auth by default
	for _, c := range certs[1:] {
		opts.Intermediates.AddCert(c)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	leaf := *certs[0]
	leaf.DNSNames = make([]string, len(certs[0].DNSNames))
	for i, n := range certs[0].DNSNames {
		leaf.DNSNames[i] = strings.TrimSuffix(n, ".")
	}
	return leaf.VerifyHostname(name)
}
