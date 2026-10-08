package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/state"
	"github.com/hugr-lab/tresor-server/internal/state/canon"
)

// The MAC (spec 014): every row that says who may use what carries one, under a data key, over its columns as
// stored - the text a column holds, so a write and a read encode the same bytes. It is written always; it is
// checked when the store is opened with MAC (state.mac), a row with none or a wrong one then ErrSealed.

// installation is the database's own id, in every MAC: a row copied from another database under the same KEK
// does not verify. Made once, by the first store that needs it.
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
	for range maxAttempts {
		var id string
		err := s.db.QueryRowContext(ctx, s.q(`SELECT instance FROM installation WHERE id = 1`)).Scan(&id)
		if err == nil {
			s.inst.id = id
			return id, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
		if s.readOnly {
			return "", errors.New("the database has no installation id yet: a serving replica makes it")
		}
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO installation (id, instance) VALUES (1, ?)`), hex.EncodeToString(raw))
		if err != nil && !s.d.Unique(err) && !s.d.Retryable(err) {
			return "", err
		}
		// made by this store, or by another meanwhile: read it again
	}
	return "", state.ErrConflict
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

// verify checks a row's MAC when the store checks MACs: none, or a wrong one, is ErrSealed - never served.
func (s *Store) verify(ctx context.Context, what, keyID string, msg func(instance string) []byte, mac []byte) error {
	if !s.checkMAC {
		return nil
	}
	if mac == nil {
		return fmt.Errorf("%w: %s has no MAC (written before spec 014: tresor-server mac adds it)", keys.ErrSealed, what)
	}
	if keyID == "" {
		return fmt.Errorf("%w: %s names no data key", keys.ErrSealed, what)
	}
	instance, err := s.instanceID(ctx)
	if err != nil {
		return err
	}
	if err := s.envelope.Verify(ctx, keyID, msg(instance), mac); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

// FillMACs gives every row with no MAC one (spec 014: tresor-server mac), as it is stored now - the operator
// vouches for the database at that moment, once, after the upgrade. A row written meanwhile keeps its own MAC:
// each update is compare-and-set on the row and its missing MAC. It returns how many rows it filled.
func (s *Store) FillMACs(ctx context.Context) (int, error) {
	if err := s.ready(); err != nil {
		return 0, err
	}
	n := 0
	for _, st := range []*Store{s, s.vars} {
		rows, err := st.query(ctx, "")
		if err != nil {
			return n, err
		}
		for _, r := range rows {
			if r.mac != nil {
				continue
			}
			mac, err := st.macOf(ctx, r.dataKeyID, st.canonical(r))
			if err != nil {
				return n, err
			}
			res, err := st.db.ExecContext(ctx, st.q(`UPDATE {entries} SET mac = ? WHERE name = ? AND version = ? AND row_id = ?
				AND mac IS NULL`), mac, r.sec.Name, r.sec.Version, r.rowID)
			if err != nil {
				return n, err
			}
			if k, _ := res.RowsAffected(); k == 1 {
				n++
			}
		}
	}
	active, err := s.envelope.ActiveID(ctx)
	if err != nil {
		return n, err
	}
	grants, err := s.db.QueryContext(ctx, s.q(`SELECT id_hash, actor_owner, actor_client, actor_issuer, user_owner, user_json,
		expires_at, subject_expires_at, subject_key_id, subject_sealed FROM delegations WHERE mac IS NULL`))
	if err != nil {
		return n, err
	}
	var pending []*delegationRow
	for grants.Next() {
		var r delegationRow
		if err := grants.Scan(&r.id, &r.actorOwner, &r.actorClient, &r.actorIssuer, &r.userOwner, &r.user, &r.expires,
			&r.subjectExpires, &r.keyID, &r.sealed); err != nil {
			grants.Close()
			return n, err
		}
		pending = append(pending, &r)
	}
	grants.Close()
	for _, r := range pending {
		if r.keyID == "" { // no subject sealed: the active data key for its MAC
			r.keyID = active
		}
		mac, err := s.macOf(ctx, r.keyID, r.canonical)
		if err != nil {
			return n, err
		}
		res, err := s.db.ExecContext(ctx, s.q(`UPDATE delegations SET subject_key_id = ?, mac = ? WHERE id_hash = ? AND mac IS NULL`),
			r.keyID, mac, r.id)
		if err != nil {
			return n, err
		}
		if k, _ := res.RowsAffected(); k == 1 {
			n++
		}
	}
	// minted tokens with no MAC are dropped, not vouched for: they are caches, minted again when needed
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM delegation_tokens WHERE mac IS NULL`))
	if err != nil {
		return n, err
	}
	if k, _ := res.RowsAffected(); k > 0 {
		s.log.Info("minted tokens with no MAC dropped: minted again when needed", "count", k)
	}
	return n, nil
}
