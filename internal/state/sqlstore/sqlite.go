package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // the "sqlite" driver

	"github.com/hugr-lab/tresor-server/internal/keys"
)

// OpenSQLite opens (creating it when missing) a SQLite database at path: WAL, foreign keys, a busy timeout,
// immediate write transactions, and the lease - one replica serves.
func OpenSQLite(ctx context.Context, path string, wrapper keys.KeyWrapper, opts Options) (*Store, error) {
	if path == "" || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("state.path: a file path, with no ? or #")
	}
	if opts.ReadOnly {
		// a reader creates nothing: a wrong path must not leave an empty database
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("state.path: %w", err)
		}
	} else {
		if dir := filepath.Dir(path); dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("state.path: %w", err)
			}
		}
		// created 0600 before SQLite opens it, whatever the umask; its WAL and shared memory files follow the
		// database's mode, and are set too in case an earlier run left them open wider
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, fmt.Errorf("state.path: %w", err)
		}
		f.Close()
		for _, p := range []string{path, path + "-wal", path + "-shm"} {
			if err := os.Chmod(p, 0o600); err != nil && !os.IsNotExist(err) {
				return nil, fmt.Errorf("state.path: %w", err)
			}
		}
	}
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(10000)")
	if opts.ReadOnly {
		// any write is refused by SQLite itself; the journal mode is the service's (setting it writes)
		q.Add("_pragma", "query_only(1)")
	} else {
		q.Add("_pragma", "journal_mode(WAL)")
		q.Add("_pragma", "synchronous(FULL)")
	}
	q.Set("_txlock", "immediate") // a write transaction takes the write lock at BEGIN: no upgrade deadlock
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("state: the SQLite database: %w", err)
	}
	s, err := open(ctx, db, SQLite, wrapper, opts)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("state: %w", err)
	}
	return s, nil
}
