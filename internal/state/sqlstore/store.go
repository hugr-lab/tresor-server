// Package sqlstore is the state.Store on a SQL database (spec 002): one set of queries in the portable
// subset, a Dialect for what differs. Params are sealed (keys.Envelope) before they reach the database;
// every write is compare-and-set on the version.
package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/state"
)

// maxAttempts bounds Update's compare-and-set retries.
const maxAttempts = 8

// Store is safe for concurrent use; on a database that allows it, by several replicas at once.
type Store struct {
	db       *sql.DB
	d        Dialect
	envelope *keys.Envelope
	log      *slog.Logger
	lease    *lease // SingleWriter dialects only
	closed   atomic.Bool
}

// Options tune a store.
type Options struct {
	Keys keys.Options
	Log  *slog.Logger
}

// open wires a store over db: the migrations, the lease where the dialect needs one, the envelope.
func open(ctx context.Context, db *sql.DB, d Dialect, wrapper keys.KeyWrapper, opts Options) (*Store, error) {
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	s := &Store{db: db, d: d, log: opts.Log}
	if err := migrate(ctx, db, d); err != nil {
		return nil, err
	}
	s.envelope = keys.NewEnvelope(wrapper, dataKeys{s}, opts.Keys)
	if d.SingleWriter {
		s.lease = newLease(db, d, opts.Log)
		s.lease.start()
	}
	return s, nil
}

func (s *Store) q(query string) string { return s.d.Rebind(query) }

// ready is the gate of every request: on a single-writer database, only the lease's holder serves.
func (s *Store) ready() error {
	if s.lease != nil && !s.lease.held() {
		return state.ErrUnavailable
	}
	return nil
}

// Envelope is the store's envelope: its Check is the KEK's readiness.
func (s *Store) Envelope() *keys.Envelope { return s.envelope }

// row is a secret as stored, its params still sealed.
type row struct {
	sec       state.Secret
	rowID     string
	dataKeyID string
	sealed    []byte
}

const secretColumns = `name, row_id, type, provider, scope, redact_keys, comment, owner, version, created_at, updated_at, data_key_id, sealed`

type scanner interface{ Scan(dest ...any) error }

func scanRow(sc scanner) (*row, error) {
	var r row
	var scope, redact string
	var created, updated int64
	err := sc.Scan(&r.sec.Name, &r.rowID, &r.sec.Type, &r.sec.Provider, &scope, &redact, &r.sec.Comment,
		&r.sec.Owner, &r.sec.Version, &created, &updated, &r.dataKeyID, &r.sealed)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(scope), &r.sec.Scope); err != nil {
		return nil, fmt.Errorf("secret %s: scope: %w", r.sec.Name, err)
	}
	if err := json.Unmarshal([]byte(redact), &r.sec.RedactKeys); err != nil {
		return nil, fmt.Errorf("secret %s: redact_keys: %w", r.sec.Name, err)
	}
	r.sec.CreatedAt, r.sec.UpdatedAt = time.UnixMicro(created).UTC(), time.UnixMicro(updated).UTC()
	return &r, nil
}

// paramsAAD binds sealed params to their row, name and version: a value copied to another row, name or
// version - or kept from a dropped secret of the same name - does not open.
func paramsAAD(rowID, name string, version int64) []byte {
	return []byte("tresor-server/params/1\x00" + rowID + "\x00" + name + "\x00" + strconv.FormatInt(version, 10))
}

func (s *Store) List(ctx context.Context) ([]*state.Secret, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+secretColumns+` FROM secrets ORDER BY name`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*state.Secret
	byName := map[string]*state.Secret{}
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		sec := r.sec // no params: a list opens no material
		out = append(out, &sec)
		byName[sec.Name] = &sec
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.grantsInto(ctx, s.db, byName, ""); err != nil {
		return nil, err
	}
	if out == nil {
		out = []*state.Secret{}
	}
	return out, nil
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// grantsInto reads the grants of the secrets in byName (of one secret, when name is set), in their order.
func (s *Store) grantsInto(ctx context.Context, q querier, byName map[string]*state.Secret, name string) error {
	query, args := `SELECT secret, id, principal, verbs FROM grants ORDER BY secret, position`, []any{}
	if name != "" {
		query, args = `SELECT secret, id, principal, verbs FROM grants WHERE secret = ? ORDER BY position`, []any{name}
	}
	rows, err := q.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var secret, verbs string
		var g state.Grant
		if err := rows.Scan(&secret, &g.ID, &g.Principal, &verbs); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(verbs), &g.Verbs); err != nil {
			return fmt.Errorf("secret %s: a grant's verbs: %w", secret, err)
		}
		if sec := byName[secret]; sec != nil {
			sec.Grants = append(sec.Grants, g)
		}
	}
	return rows.Err()
}

// get reads one secret as stored, or nil when there is none.
func (s *Store) get(ctx context.Context, name string) (*row, error) {
	r, err := scanRow(s.db.QueryRowContext(ctx, s.q(`SELECT `+secretColumns+` FROM secrets WHERE name = ?`), name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.grantsInto(ctx, s.db, map[string]*state.Secret{name: &r.sec}, name); err != nil {
		return nil, err
	}
	return r, nil
}

// opened is a row's secret with its params open.
func (s *Store) opened(ctx context.Context, r *row) (*state.Secret, error) {
	plain, err := s.envelope.Open(ctx, r.dataKeyID, paramsAAD(r.rowID, r.sec.Name, r.sec.Version), r.sealed)
	if err != nil {
		return nil, fmt.Errorf("secret %s: its params: %w", r.sec.Name, err)
	}
	sec := r.sec
	if err := json.Unmarshal(plain, &sec.Params); err != nil {
		return nil, fmt.Errorf("secret %s: its params: %w", r.sec.Name, keys.ErrSealed)
	}
	clear(plain)
	return &sec, nil
}

func (s *Store) Get(ctx context.Context, name string) (*state.Secret, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	r, err := s.get(ctx, name)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, state.ErrNotFound
	}
	return s.opened(ctx, r)
}

func (s *Store) Update(ctx context.Context, name string,
	fn func(current *state.Secret) (*state.Secret, error)) (*state.Secret, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	for range maxAttempts {
		r, err := s.get(ctx, name)
		if err != nil {
			return nil, err
		}
		var current *state.Secret
		if r != nil {
			// a secret whose params do not open is never rewritten blind
			if current, err = s.opened(ctx, r); err != nil {
				return nil, err
			}
		}
		next, err := fn(state.Clone(current))
		if err != nil {
			return nil, err
		}
		if err := state.CheckVersion(current, next); err != nil {
			return nil, err
		}
		var done bool
		switch {
		case next == nil && current == nil:
			return nil, state.ErrNotFound
		case next == nil:
			done, err = s.remove(ctx, name, current.Version)
		default:
			next = state.Clone(next)
			next.Name = name
			done, err = s.write(ctx, r, next)
		}
		if err != nil {
			return nil, err
		}
		if done {
			return next, nil
		}
		// another writer came first: run fn again on what it wrote
	}
	return nil, state.ErrConflict
}

// remove deletes a secret at a version; false when the version moved on.
func (s *Store) remove(ctx context.Context, name string, version int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM secrets WHERE name = ? AND version = ?`), name, version)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// write creates next (r nil) or replaces r by it, compare-and-set on r's version; false when another writer
// came first.
func (s *Store) write(ctx context.Context, r *row, next *state.Secret) (bool, error) {
	rowID := ""
	if r != nil {
		rowID = r.rowID
	} else {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return false, err
		}
		rowID = hex.EncodeToString(raw)
	}
	plain, err := json.Marshal(next.Params)
	if err != nil {
		return false, err
	}
	dataKeyID, sealed, err := s.envelope.Seal(ctx, paramsAAD(rowID, next.Name, next.Version), plain)
	clear(plain)
	if err != nil {
		return false, err
	}
	scope, _ := json.Marshal(next.Scope)
	redact, _ := json.Marshal(next.RedactKeys)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	args := []any{next.Type, next.Provider, string(scope), string(redact), next.Comment, next.Owner, next.Version,
		next.CreatedAt.UnixMicro(), next.UpdatedAt.UnixMicro(), dataKeyID, sealed}
	if r == nil {
		_, err := tx.ExecContext(ctx, s.q(`INSERT INTO secrets (`+secretColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`), append([]any{next.Name, rowID}, args...)...)
		if s.d.Unique(err) {
			return false, nil // created by another writer meanwhile
		}
		if err != nil {
			return false, err
		}
	} else {
		res, err := tx.ExecContext(ctx, s.q(`UPDATE secrets SET type = ?, provider = ?, scope = ?, redact_keys = ?,
			comment = ?, owner = ?, version = ?, created_at = ?, updated_at = ?, data_key_id = ?, sealed = ?
			WHERE name = ? AND version = ?`), append(args, next.Name, r.sec.Version)...)
		if err != nil {
			return false, err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM grants WHERE secret = ?`), next.Name); err != nil {
			return false, err
		}
	}
	for i, g := range next.Grants {
		verbs, _ := json.Marshal(g.Verbs)
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO grants (secret, id, position, principal, verbs)
			VALUES (?, ?, ?, ?, ?)`), next.Name, g.ID, i, g.Principal, string(verbs)); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

// Ping says whether the store answers, and on a single-writer database whether this replica holds it.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return err
	}
	if s.lease != nil && !s.lease.held() {
		return errors.New("another replica holds the SQLite database: waiting for its lease")
	}
	return nil
}

func (s *Store) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	if s.lease != nil {
		s.lease.stop()
	}
	return s.db.Close()
}
