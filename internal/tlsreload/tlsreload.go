// Package tlsreload serves a certificate and key from files, read again when they change (spec 029): a
// certificate renewed in place - cert-manager's Secret, mounted as files - is served without a restart. A new pair
// is checked whole (the key the certificate's, the certificate in date) before it serves; a bad one leaves the old
// pair serving, and says so. Nothing of the key is ever logged.
package tlsreload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Reloader holds the pair in service.
type Reloader struct {
	certFile, keyFile string
	log               *slog.Logger
	now               func() time.Time

	mu      sync.RWMutex
	cert    *tls.Certificate
	leaf    *x509.Certificate
	sum     [32]byte // of the files the pair in service was read from
	lastErr error    // the last reload's failure, until one succeeds
}

// New reads the pair: a start with a pair that does not load fails.
func New(certFile, keyFile string, log *slog.Logger) (*Reloader, error) {
	r := &Reloader{certFile: certFile, keyFile: keyFile, log: log, now: time.Now}
	if _, err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// GetCertificate is tls.Config's: the pair in service.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// Watch reads the files every interval until ctx ends, and takes a changed pair once it checks.
func (r *Reloader) Watch(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			changed, err := r.reload()
			switch {
			case err != nil:
				r.log.Error("the TLS certificate's new files do not load: the old pair serves", "error", err.Error())
			case changed:
				r.mu.RLock()
				leaf := r.leaf
				r.mu.RUnlock()
				r.log.Info("the TLS certificate reloaded", "subject", leaf.Subject.String(),
					"not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
			}
		}
	}
}

// reload reads the files; a pair unchanged since the last read is not parsed again.
func (r *Reloader) reload() (bool, error) {
	certPEM, err := os.ReadFile(r.certFile)
	if err != nil {
		return false, r.fail(fmt.Errorf("tls.cert: %w", err))
	}
	keyPEM, err := os.ReadFile(r.keyFile)
	if err != nil {
		return false, r.fail(fmt.Errorf("tls.key: %w", err))
	}
	sum := sha256.Sum256(append(append(bytes.Clone(certPEM), 0), keyPEM...))
	r.mu.RLock()
	same := r.cert != nil && sum == r.sum
	r.mu.RUnlock()
	if same {
		return false, nil
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM) // the key the certificate's
	if err != nil {
		return false, r.fail(errors.New("tls.cert and tls.key are not a pair (or do not parse)"))
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false, r.fail(errors.New("tls.cert does not parse"))
	}
	if now := r.now(); now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
		return false, r.fail(fmt.Errorf("tls.cert is out of date (valid %s to %s)", leaf.NotBefore.UTC().Format(time.RFC3339),
			leaf.NotAfter.UTC().Format(time.RFC3339)))
	}
	pair.Leaf = leaf
	r.mu.Lock()
	r.cert, r.leaf, r.sum, r.lastErr = &pair, leaf, sum, nil
	r.mu.Unlock()
	return true, nil
}

func (r *Reloader) fail(err error) error {
	r.mu.Lock()
	r.lastErr = err
	r.mu.Unlock()
	return err
}

// Check is readiness's: the last reload's failure (the old pair still serving), or the pair in service out of
// date.
func (r *Reloader) Check(context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.lastErr != nil {
		return r.lastErr
	}
	if r.now().After(r.leaf.NotAfter) {
		return fmt.Errorf("the TLS certificate in service expired at %s", r.leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}
