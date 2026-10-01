package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

type migration struct {
	version int
	name    string
	sql     string
}

// dialectMigrations are a dialect's embedded migrations (migrations/<dialect>/NNNN_name.sql), in order.
func dialectMigrations(d Dialect) ([]migration, error) {
	dir := path.Join("migrations", d.Name)
	entries, err := fs.ReadDir(migrations, dir)
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		num, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil || !strings.HasSuffix(e.Name(), ".sql") {
			return nil, fmt.Errorf("migration %s: not NNNN_name.sql", e.Name())
		}
		body, err := fs.ReadFile(migrations, path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: e.Name(), sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// migrate applies what the database lacks, each migration in a transaction of its own; a database migrated
// by a newer binary is refused, never written.
func migrate(ctx context.Context, db *sql.DB, d Dialect) error {
	all, err := dialectMigrations(d)
	if err != nil {
		return err
	}
	if err := bootstrap(ctx, db, d); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	var newest sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&newest); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	if known := all[len(all)-1].version; newest.Valid && int(newest.Int64) > known {
		return fmt.Errorf("the database is at migration %d, this binary knows %d: refusing an older binary",
			newest.Int64, known)
	}
	for _, m := range all {
		if newest.Valid && m.version <= int(newest.Int64) {
			continue
		}
		if err := apply(ctx, db, d, m); err != nil {
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
	}
	return nil
}

// bootstrap makes the migrations' table, under the migrations' lock: replicas starting at once on an empty
// database would race even on CREATE TABLE IF NOT EXISTS (PostgreSQL: a duplicate type in its catalog).
func bootstrap(ctx context.Context, db *sql.DB, d Dialect) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := d.Lock(ctx, tx, "tresor-server/migrate"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, d.Bootstrap); err != nil {
		return err
	}
	return tx.Commit()
}

func apply(ctx context.Context, db *sql.DB, d Dialect, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// one replica migrates at a time; one that waited finds it applied
	if err := d.Lock(ctx, tx, "tresor-server/migrate"); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRowContext(ctx, d.Rebind(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`), m.version).
		Scan(&n); err != nil || n > 0 {
		return err
	}
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, d.Rebind(`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`),
		m.version, m.name, time.Now().UnixMicro()); err != nil {
		return err
	}
	return tx.Commit()
}
