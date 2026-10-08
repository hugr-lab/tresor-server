package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel/attribute"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/state/canon"
	"github.com/hugr-lab/tresor-server/internal/telemetry"
)

// The MAC (spec 014): every row that says who may use what carries one, under a data key, over its columns as
// stored - the text a column holds, so a write and a read encode the same bytes. It is written always; it is
// checked when the store is opened with MAC (state.mac), a row with none or a wrong one then ErrSealed.

// installation is the database's own id, in every MAC: a row copied from another database under the same KEK
// does not verify. Made once, by the migration (0006); a store never makes another - a missing row is an error,
// since a new id would refuse every row there is.
type installation struct {
	mu sync.Mutex
	id string
}

func (s *Store) instanceID(ctx context.Context) (string, error) {
	s.inst.mu.Lock()
	defer s.inst.mu.Unlock()
	if s.inst.id != "" {
		return s.inst.id, nil
	}
	var id string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT instance FROM installation WHERE id = 1`)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && id == "") {
		return "", errors.New("the database's installation id is missing (the installation table's row): every MAC depends " +
			"on it - restore it from a backup; a new one would refuse every row")
	}
	if err != nil {
		return "", err
	}
	s.inst.id = id
	return id, nil
}

// rowCanon is a secret's or a variable's row with its grants, as stored.
func rowCanon(ns namespace, instance string, r *row) []byte {
	c := canon.New("sql/"+ns.entries, instance)
	c.Str(r.sec.Name)
	c.Str(r.rowID)
	c.Str(r.sec.Type)
	c.Str(r.sec.Provider)
	c.Str(r.scopeText)
	c.Str(r.redactText)
	c.Str(r.sec.Comment)
	c.Str(r.sec.Owner)
	c.I64(r.sec.Version)
	c.I64(r.createdMicro)
	c.I64(r.updatedMicro)
	c.Count(false, len(r.grantRows))
	for _, g := range r.grantRows {
		c.Str(g.id)
		c.Str(g.principal)
		c.Str(g.verbs)
	}
	c.Str(r.dataKeyID)
	c.Bytes(r.sealed)
	return *c
}

// delegationRow is a delegation grant as stored.
type delegationRow struct {
	id, actorOwner, actorClient, actorIssuer, userOwner, user string
	expires, subjectExpires                                   int64
	keyID                                                     string
	sealed, mac                                               []byte
}

func (g *delegationRow) canonical(instance string) []byte {
	c := canon.New("sql/delegations", instance)
	c.Str(g.id)
	c.Str(g.actorOwner)
	c.Str(g.actorClient)
	c.Str(g.actorIssuer)
	c.Str(g.userOwner)
	c.Str(g.user)
	c.I64(g.expires)
	c.I64(g.subjectExpires)
	c.Str(g.keyID)
	c.Bytes(g.sealed)
	return *c
}

// tokenRow is a minted token as stored; the MAC is over the key's column (its hash, as stored - the AAD of its
// sealed value names the key itself).
type tokenRow struct {
	id, key string
	version int64
	failed  string
	keyID   string
	sealed  []byte
	mac     []byte
}

func (t *tokenRow) canonical(instance string) []byte {
	c := canon.New("sql/delegation_tokens", instance)
	c.Str(t.id)
	c.Str(mintKeyColumn(t.key))
	c.I64(t.version)
	c.Str(t.failed)
	c.Str(t.keyID)
	c.Bytes(t.sealed)
	return *c
}

// macOf is msg's MAC under the data key keyID, in this installation.
func (s *Store) macOf(ctx context.Context, keyID string, msg func(instance string) []byte) ([]byte, error) {
	instance, err := s.instanceID(ctx)
	if err != nil {
		return nil, err
	}
	return s.envelope.MAC(ctx, keyID, msg(instance))
}

// verify checks a row's MAC. With the checks on (state.mac), none or a wrong one is ErrSealed - never served.
// With them off, a wrong one is logged and counted, not refused: nothing changed behind the store goes unseen until
// the checks are turned on.
func (s *Store) verify(ctx context.Context, what, keyID string, msg func(instance string) []byte, mac []byte) error {
	if mac == nil {
		if s.checkMAC {
			return fmt.Errorf("%w: %s has no MAC (written before spec 014: tresor-server mac adds it)", keys.ErrSealed, what)
		}
		return nil
	}
	err := s.check(ctx, keyID, msg, mac)
	if err == nil || !errors.Is(err, keys.ErrSealed) {
		return err
	}
	if s.checkMAC {
		return fmt.Errorf("%s: %w", what, err)
	}
	telemetry.Add(ctx, telemetry.StateLeftOut, attribute.String("kind", "unchecked"))
	s.log.Warn("a row's MAC does not verify (state.mac is off: served anyway)", "row", what, "error", err.Error())
	return nil
}

// check is a MAC's verification: ErrSealed when it does not match, or names no data key.
func (s *Store) check(ctx context.Context, keyID string, msg func(instance string) []byte, mac []byte) error {
	if keyID == "" {
		return fmt.Errorf("%w: the row names no data key", keys.ErrSealed)
	}
	instance, err := s.instanceID(ctx)
	if err != nil {
		return err
	}
	return s.envelope.Verify(ctx, keyID, msg(instance), mac)
}

// FillMACs gives every row with no MAC, or one that does not verify, a MAC (spec 014: tresor-server mac), as
// the row is stored now - the operator vouches for the database at that moment, once, after every replica runs a
// binary that writes MACs (an older one rewrites rows and leaves their MAC stale). Each update is compare-and-set
// on the row and the MAC read. A row that cannot be given one (its data key missing) is named in the log and
// skipped. It returns how many rows it filled, and how many it skipped.
func (s *Store) FillMACs(ctx context.Context) (filled, skipped int, err error) {
	if err := s.ready(); err != nil {
		return 0, 0, err
	}
	// stale: a MAC that does not verify; an outage is not a reason to vouch
	stale := func(keyID string, msg func(string) []byte, mac []byte) (bool, error) {
		if mac == nil {
			return true, nil
		}
		err := s.check(ctx, keyID, msg, mac)
		if errors.Is(err, keys.ErrSealed) {
			return true, nil
		}
		return false, err
	}
	skip := func(what string, err error) {
		skipped++
		s.log.Warn("tresor-server mac: a row left as it is", "row", what, "error", err.Error())
	}
	for _, st := range []*Store{s, s.vars} {
		rows, err := st.query(ctx, "")
		if err != nil {
			return filled, skipped, err
		}
		for _, r := range rows {
			what := st.ns.entries + " " + r.sec.Name
			redo, err := stale(r.dataKeyID, st.canonical(r), r.mac)
			if err != nil {
				return filled, skipped, err
			}
			if !redo {
				continue
			}
			mac, err := st.macOf(ctx, r.dataKeyID, st.canonical(r))
			if err != nil {
				skip(what, err)
				continue
			}
			// compare-and-set on the row and the MAC read (NULL, or the stale one)
			query, args := `UPDATE {entries} SET mac = ? WHERE name = ? AND version = ? AND row_id = ? AND mac IS NULL`,
				[]any{mac, r.sec.Name, r.sec.Version, r.rowID}
			if r.mac != nil {
				query, args = `UPDATE {entries} SET mac = ? WHERE name = ? AND version = ? AND row_id = ? AND mac = ?`, append(args, r.mac)
			}
			res, err := st.db.ExecContext(ctx, st.q(query), args...)
			if err != nil {
				return filled, skipped, err
			}
			if k, _ := res.RowsAffected(); k == 1 {
				filled++
			}
		}
	}
	active, err := s.envelope.ActiveID(ctx)
	if err != nil {
		return filled, skipped, err
	}
	grants, err := s.db.QueryContext(ctx, s.q(`SELECT id_hash, actor_owner, actor_client, actor_issuer, user_owner, user_json,
		expires_at, subject_expires_at, subject_key_id, subject_sealed, mac FROM delegations`))
	if err != nil {
		return filled, skipped, err
	}
	var pending []*delegationRow
	for grants.Next() {
		var r delegationRow
		if err := grants.Scan(&r.id, &r.actorOwner, &r.actorClient, &r.actorIssuer, &r.userOwner, &r.user, &r.expires,
			&r.subjectExpires, &r.keyID, &r.sealed, &r.mac); err != nil {
			grants.Close()
			return filled, skipped, err
		}
		pending = append(pending, &r)
	}
	grants.Close()
	for _, r := range pending {
		old := r.mac
		if r.keyID != "" {
			redo, err := stale(r.keyID, r.canonical, r.mac)
			if err != nil {
				return filled, skipped, err
			}
			if !redo {
				continue
			}
		} else { // no subject sealed: the active data key for its MAC
			r.keyID = active
		}
		mac, err := s.macOf(ctx, r.keyID, r.canonical)
		if err != nil {
			skip("a delegation grant", err)
			continue
		}
		query, args := `UPDATE delegations SET subject_key_id = ?, mac = ? WHERE id_hash = ? AND mac IS NULL`, []any{r.keyID, mac, r.id}
		if old != nil {
			query, args = `UPDATE delegations SET subject_key_id = ?, mac = ? WHERE id_hash = ? AND mac = ?`, append(args, old)
		}
		res, err := s.db.ExecContext(ctx, s.q(query), args...)
		if err != nil {
			return filled, skipped, err
		}
		if k, _ := res.RowsAffected(); k == 1 {
			filled++
		}
	}
	// minted tokens with no MAC are dropped, not vouched for: they are caches, minted again when needed
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM delegation_tokens WHERE mac IS NULL`))
	if err != nil {
		return filled, skipped, err
	}
	if k, _ := res.RowsAffected(); k > 0 {
		s.log.Info("minted tokens with no MAC dropped: minted again when needed", "count", k)
	}
	return filled, skipped, nil
}
