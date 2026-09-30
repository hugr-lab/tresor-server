package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// The lease (spec 002): on a single-writer database one replica serves at a time. It holds the lease row
// and renews it; another waits - serving nothing, not ready - until the lease is free or expired. A row, not
// a file lock: file locks are not reliable on network shares.
var (
	leaseTTL   = 15 * time.Second
	leaseRenew = 5 * time.Second // tests shorten both
)

type lease struct {
	db     *sql.DB
	d      Dialect
	log    *slog.Logger
	holder string
	now    func() time.Time

	holding atomic.Bool
	done    chan struct{}
	wg      sync.WaitGroup
}

func newLease(db *sql.DB, d Dialect, log *slog.Logger) *lease {
	raw := make([]byte, 8)
	_, _ = rand.Read(raw)
	return &lease{db: db, d: d, log: log, holder: hex.EncodeToString(raw), now: time.Now, done: make(chan struct{})}
}

func (l *lease) held() bool { return l.holding.Load() }

// start takes the lease now if it is free, then keeps taking or renewing it.
func (l *lease) start() {
	l.try()
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
				l.try()
			}
		}
	}()
}

// try takes the lease when it is ours, free or expired, and renews it; a replica that cannot stops serving.
func (l *lease) try() {
	ctx, cancel := context.WithTimeout(context.Background(), leaseRenew)
	defer cancel()
	now := l.now()
	ok, err := l.acquire(ctx, now)
	was := l.holding.Swap(ok && err == nil)
	switch {
	case err != nil:
		l.log.Error("the SQLite lease could not be renewed: serving nothing until it is", "error", err.Error())
	case ok && !was:
		l.log.Info("the SQLite lease is held: serving")
	case !ok && was:
		l.log.Warn("the SQLite lease was lost to another replica: serving nothing")
	case !ok:
		l.log.Info("another replica holds the SQLite lease: waiting")
	}
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
	if l.holding.Swap(false) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = l.db.ExecContext(ctx, l.d.Rebind(`UPDATE lease SET expires_at = 0 WHERE id = 1 AND holder = ?`), l.holder)
	}
}
