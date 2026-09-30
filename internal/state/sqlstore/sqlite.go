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
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("state.path: %w", err)
		}
	}
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Set("_txlock", "immediate") // a write transaction takes the write lock at BEGIN: no upgrade deadlock
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("state: the SQLite database: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("state.path: %w", err)
	}
	s, err := open(ctx, db, SQLite, wrapper, opts)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("state: %w", err)
	}
	return s, nil
}
