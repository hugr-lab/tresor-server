package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"
)

// The lease (spec 002): on a single-writer database one replica serves at a time. It holds the lease row
// and renews it; another waits - serving nothing, not ready - until the lease is free or expired. A row, not
// a file lock: file locks are not reliable on network shares.
//
// Fencing: the holder serves only until its own monotonic deadline, leaseMargin before the expiry it wrote -
// a process paused past it (a GC, a suspended VM) stops serving before another replica may take over, and
// clocks may differ by up to leaseMargin.
var (
	leaseTTL    = 15 * time.Second
	leaseRenew  = 5 * time.Second
	leaseMargin = 5 * time.Second // tests shorten all three
)

type lease struct {
	db     *sql.DB
	d      Dialect
	log    *slog.Logger
	holder string
	onHeld func(context.Context) error // runs while held (the migrations): an error keeps the store unready

	mu        sync.Mutex
	heldUntil time.Time // monotonic
	done      chan struct{}
	wg        sync.WaitGroup
}

// newLease makes the lease's table, outside the migrations: a replica must hold the lease before it
// migrates.
func newLease(ctx context.Context, db *sql.DB, d Dialect, log *slog.Logger, onHeld func(context.Context) error) (*lease, error) {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS lease (
		id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1), holder TEXT NOT NULL, expires_at INTEGER NOT NULL)`); err != nil {
		return nil, err
	}
	raw := make([]byte, 8)
	_, _ = rand.Read(raw)
	return &lease{db: db, d: d, log: log, holder: hex.EncodeToString(raw), onHeld: onHeld, done: make(chan struct{})}, nil
}

func (l *lease) held() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return time.Now().Before(l.heldUntil)
}

// start tries the lease now - an error when it is held and onHeld fails - then keeps trying and renewing.
func (l *lease) start(ctx context.Context) error {
	if err := l.try(ctx); err != nil {
		return err
	}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		ticker := time.NewTicker(leaseRenew)
		defer ticker.Stop()
		for {
			select {
			case <-l.done:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), leaseRenew)
				if err := l.try(ctx); err != nil {
					l.log.Error("the SQLite database could not be prepared: not ready", "error", err.Error())
				}
				cancel()
			}
		}
	}()
	return nil
}

// try takes the lease when it is ours, free or expired, and renews it. A failed renewal does not drop it at
// once: the deadline does (a transient busy database must not flap the replica).
func (l *lease) try(ctx context.Context) error {
	was := l.held()
	attempt := time.Now()
	ok, err := l.acquire(ctx, attempt)
	switch {
	case err != nil:
		l.log.Warn("the SQLite lease was not renewed", "error", err.Error())
	case ok:
		l.mu.Lock()
		l.heldUntil = attempt.Add(leaseTTL - leaseMargin)
		l.mu.Unlock()
	default:
		l.mu.Lock()
		l.heldUntil = time.Time{}
		l.mu.Unlock()
	}
	now := l.held()
	switch {
	case now && !was:
		l.log.Info("the SQLite lease is held: serving")
	case !now && was:
		l.log.Warn("the SQLite lease is lost: serving nothing")
	case !now && err == nil:
		l.log.Info("another replica holds the SQLite lease: waiting")
	}
	if now {
		return l.onHeld(ctx)
	}
	return nil
}

func (l *lease) acquire(ctx context.Context, now time.Time) (bool, error) {
	expires := now.Add(leaseTTL).UnixMicro()
	res, err := l.db.ExecContext(ctx, l.d.Rebind(`UPDATE lease SET holder = ?, expires_at = ?
		WHERE id = 1 AND (holder = ? OR expires_at < ?)`), l.holder, expires, l.holder, now.UnixMicro())
	if err != nil {
		return false, err
	}
	if n, err := res.RowsAffected(); err != nil || n == 1 {
		return err == nil, err
	}
	_, err = l.db.ExecContext(ctx, l.d.Rebind(`INSERT INTO lease (id, holder, expires_at) VALUES (1, ?, ?)`),
		l.holder, expires)
	if l.d.Unique(err) {
		return false, nil // held by another replica, and not expired
	}
	return err == nil, err
}

// stop ends the renewals and frees the lease: a replica that starts next need not wait for it to expire.
func (l *lease) stop() {
	close(l.done)
	l.wg.Wait()
	l.mu.Lock()
	l.heldUntil = time.Time{}
	l.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = l.db.ExecContext(ctx, l.d.Rebind(`UPDATE lease SET expires_at = 0 WHERE id = 1 AND holder = ?`), l.holder)
}
