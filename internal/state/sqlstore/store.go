// Package sqlstore is the state.Store on a SQL database (spec 002): one set of queries in the portable
// subset, a Dialect for what differs. Params are sealed (keys.Envelope) before they reach the database;
// every write is compare-and-set on the row - its version and its row id.
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
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/state"
	"github.com/hugr-lab/tresor-server/internal/telemetry"
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
	migrated *atomic.Bool
	closed   *atomic.Bool
	ns       namespace
	vars     *Store // spec 004: the variables' namespace, on the same database

	// beforeWrite, in tests, runs between fn and the compare-and-set: another writer's moment.
	beforeWrite func()
}

// Options tune a store.
type Options struct {
	Keys keys.Options
	Log  *slog.Logger
}

// open wires a store over db: the envelope, the lease where the dialect needs one, the migrations. On a
// single-writer database the migrations run once the lease is held: a replica that waits must not change
// the schema under the one that serves.
func open(ctx context.Context, db *sql.DB, d Dialect, wrapper keys.KeyWrapper, opts Options) (*Store, error) {
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	s := &Store{db: db, d: d, log: opts.Log, migrated: &atomic.Bool{}, closed: &atomic.Bool{}, ns: secretsNS}
	s.envelope = keys.NewEnvelope(wrapper, dataKeys{s}, opts.Keys)
	defer s.linkVariables() // after the lease: the variables' store shares it
	if !d.SingleWriter {
		if err := migrate(ctx, db, d); err != nil {
			return nil, err
		}
		s.migrated.Store(true)
		return s, nil
	}
	l, err := newLease(ctx, db, d, opts.Log, s.migrateOnce)
	if err != nil {
		return nil, err
	}
	s.lease = l
	if err := l.start(ctx); err != nil {
		return nil, err // held at once, and the database cannot be migrated: nothing to serve
	}
	return s, nil
}

// migrateOnce migrates when the lease is first held.
func (s *Store) migrateOnce(ctx context.Context) error {
	if s.migrated.Load() {
		return nil
	}
	if err := migrate(ctx, s.db, s.d); err != nil {
		return err
	}
	s.migrated.Store(true)
	return nil
}

// namespace is what one store keeps (spec 004): the secrets, or the variables - the same shape, tables of
// their own, and an AAD of their own, so a sealed value never opens in the other.
type namespace struct {
	entries, grants string // the tables
	aad             string
}

var (
	secretsNS   = namespace{entries: "secrets", grants: "grants", aad: "tresor-server/params/1"}
	variablesNS = namespace{entries: "variables", grants: "variable_grants", aad: "tresor-server/variable/1"}
)

// linkVariables makes the variables' store: this one's database, envelope, lease and state.
func (s *Store) linkVariables() {
	v := *s
	v.ns, v.beforeWrite = variablesNS, nil
	v.vars = &v
	s.vars = &v
}

// Variables is the variables' namespace (spec 004). Closing it closes nothing: the database is this store's.
func (s *Store) Variables() state.Store { return s.vars }

// q is a query for this namespace's tables ({entries}, {grants}), in the dialect's placeholders.
func (s *Store) q(query string) string {
	return s.d.Rebind(strings.NewReplacer("{entries}", s.ns.entries, "{grants}", s.ns.grants).Replace(query))
}

// ready is the gate of every request: on a single-writer database, only the lease's holder serves, and
// only once its schema is current.
func (s *Store) ready() error {
	if s.lease != nil && !s.lease.held() {
		return state.ErrUnavailable
	}
	if !s.migrated.Load() {
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

// selectSecrets reads secrets with their grants in one statement: one snapshot, the grants in their order.
const selectSecrets = `SELECT s.name, s.row_id, s.type, s.provider, s.scope, s.redact_keys, s.comment, s.owner,
	s.version, s.created_at, s.updated_at, s.data_key_id, s.sealed, g.id, g.principal, g.verbs
	FROM {entries} s LEFT JOIN {grants} g ON g.secret = s.name`

const secretColumns = `name, row_id, type, provider, scope, redact_keys, comment, owner, version, created_at, updated_at, data_key_id, sealed`

// query reads secrets (one, when name is set), in name order.
func (s *Store) query(ctx context.Context, name string) ([]*row, error) {
	query, args := selectSecrets+` ORDER BY s.name, g.position`, []any{}
	if name != "" {
		query, args = selectSecrets+` WHERE s.name = ? ORDER BY g.position`, []any{name}
	}
	rows, err := s.db.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*row
	for rows.Next() {
		var r row
		var scope, redact string
		var created, updated int64
		var gID, gPrincipal, gVerbs sql.NullString
		if err := rows.Scan(&r.sec.Name, &r.rowID, &r.sec.Type, &r.sec.Provider, &scope, &redact, &r.sec.Comment,
			&r.sec.Owner, &r.sec.Version, &created, &updated, &r.dataKeyID, &r.sealed,
			&gID, &gPrincipal, &gVerbs); err != nil {
			return nil, err
		}
		if n := len(out); n == 0 || out[n-1].sec.Name != r.sec.Name {
			if err := json.Unmarshal([]byte(scope), &r.sec.Scope); err != nil {
				return nil, fmt.Errorf("secret %s: scope: %w", r.sec.Name, err)
			}
			if err := json.Unmarshal([]byte(redact), &r.sec.RedactKeys); err != nil {
				return nil, fmt.Errorf("secret %s: redact_keys: %w", r.sec.Name, err)
			}
			r.sec.CreatedAt, r.sec.UpdatedAt = time.UnixMicro(created).UTC(), time.UnixMicro(updated).UTC()
			out = append(out, &r)
		}
		if gID.Valid {
			g := state.Grant{ID: gID.String, Principal: gPrincipal.String}
			if err := json.Unmarshal([]byte(gVerbs.String), &g.Verbs); err != nil {
				return nil, fmt.Errorf("secret %s: a grant's verbs: %w", r.sec.Name, err)
			}
			last := out[len(out)-1]
			last.sec.Grants = append(last.sec.Grants, g)
		}
	}
	return out, rows.Err()
}

// get reads one secret as stored, or nil when there is none.
func (s *Store) get(ctx context.Context, name string) (*row, error) {
	rows, err := s.query(ctx, name)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

// paramsAAD binds sealed params to their namespace, row, name and version: a value copied to another
// namespace, row, name or version - or kept from a dropped secret of the same name - does not open.
func (s *Store) paramsAAD(rowID, name string, version int64) []byte {
	return []byte(s.ns.aad + "\x00" + rowID + "\x00" + name + "\x00" + strconv.FormatInt(version, 10))
}

// opened is a row's secret with its params open.
func (s *Store) opened(ctx context.Context, r *row) (*state.Secret, error) {
	plain, err := s.envelope.Open(ctx, r.dataKeyID, s.paramsAAD(r.rowID, r.sec.Name, r.sec.Version), r.sealed)
	if err != nil {
		return nil, fmt.Errorf("secret %s: its params: %w", r.sec.Name, err)
	}
	sec := r.sec
	err = json.Unmarshal(plain, &sec.Params)
	clear(plain)
	if err != nil {
		return nil, fmt.Errorf("secret %s: its params: %w", r.sec.Name, keys.ErrSealed)
	}
	return &sec, nil
}

func (s *Store) List(ctx context.Context) ([]*state.Secret, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	rows, err := s.query(ctx, "")
	if err != nil {
		return nil, err
	}
	out := make([]*state.Secret, len(rows))
	for i, r := range rows {
		sec := r.sec // no params: a list opens no material
		out[i] = &sec
	}
	return out, nil
}

func (s *Store) Describe(ctx context.Context, name string) (*state.Secret, error) {
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
	sec := r.sec
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
		var broken error // the params do not open: only a delete may pass
		if r != nil {
			current, err = s.opened(ctx, r)
			if errors.Is(err, keys.ErrSealed) {
				broken, current = err, state.Clone(&r.sec)
			} else if err != nil {
				return nil, err // the KEK may be unreachable: nothing is decided on a guess
			}
		}
		next, err := fn(state.Clone(current))
		if err != nil {
			return nil, err
		}
		if broken != nil && next != nil {
			return nil, broken // never rewritten blind; an admin may delete it
		}
		if err := state.CheckVersion(current, next); err != nil {
			return nil, err
		}
		if s.beforeWrite != nil {
			s.beforeWrite()
		}
		var done bool
		switch {
		case next == nil && current == nil:
			return nil, state.ErrNotFound
		case next == nil:
			done, err = s.remove(ctx, r)
		default:
			next = state.Clone(next)
			next.Name = name
			done, err = s.write(ctx, r, next)
		}
		if err != nil && !s.d.Retryable(err) {
			return nil, err
		}
		if done {
			return next, nil
		}
		// another writer came first (or the database gave the transaction up): run fn again on what is there
		telemetry.Add(ctx, telemetry.StateConflicts, attribute.String("operation", "update"))
	}
	return nil, state.ErrConflict
}

// remove deletes the row r was read from; false when it changed or was replaced meanwhile. The row id is
// in the compare: a secret dropped and created again starts at version 1 again.
func (s *Store) remove(ctx context.Context, r *row) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM {entries} WHERE name = ? AND version = ? AND row_id = ?`),
		r.sec.Name, r.sec.Version, r.rowID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// write creates next (r nil) or replaces r's row by it, compare-and-set on its version and row id; false
// when another writer came first.
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
	dataKeyID, sealed, err := s.envelope.Seal(ctx, s.paramsAAD(rowID, next.Name, next.Version), plain)
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
		_, err := tx.ExecContext(ctx, s.q(`INSERT INTO {entries} (`+secretColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`), append([]any{next.Name, rowID}, args...)...)
		if s.d.Unique(err) {
			return false, nil // created by another writer meanwhile
		}
		if err != nil {
			return false, err
		}
	} else {
		res, err := tx.ExecContext(ctx, s.q(`UPDATE {entries} SET type = ?, provider = ?, scope = ?, redact_keys = ?,
			comment = ?, owner = ?, version = ?, created_at = ?, updated_at = ?, data_key_id = ?, sealed = ?
			WHERE name = ? AND version = ? AND row_id = ?`), append(args, next.Name, r.sec.Version, r.rowID)...)
		if err != nil {
			return false, err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM {grants} WHERE secret = ?`), next.Name); err != nil {
			return false, err
		}
	}
	for i, g := range next.Grants {
		verbs, _ := json.Marshal(g.Verbs)
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO {grants} (secret, id, position, principal, verbs)
			VALUES (?, ?, ?, ?, ?)`), next.Name, g.ID, i, g.Principal, string(verbs)); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

// Ping says whether the store answers, and on a single-writer database whether this replica serves it.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return err
	}
	if s.lease != nil && !s.lease.held() {
		return errors.New("another replica holds the SQLite database: waiting for its lease")
	}
	if !s.migrated.Load() {
		return errors.New("the database's schema is not current (see the log)")
	}
	return nil
}

func (s *Store) Close() error {
	if s.ns != secretsNS {
		return nil // the variables' store: the database is the secrets' store's
	}
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	if s.lease != nil {
		s.lease.stop()
	}
	return s.db.Close()
}
