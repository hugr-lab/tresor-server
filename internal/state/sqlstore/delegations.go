package sqlstore

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/hugr-lab/tresor-server/internal/state"
)

// delegations is the store's state.DelegationStore: the subject token and the minted tokens sealed under
// the envelope, the AAD naming the grant (and the token's key and version).
type delegations struct{ s *Store }

func (s *Store) Delegations() state.DelegationStore { return delegations{s} }

func subjectAAD(idHash string) []byte { return []byte("tresor-server/delegation/1\x00" + idHash) }

func tokenAAD(idHash, key string, version int64) []byte {
	return []byte("tresor-server/minted/1\x00" + idHash + "\x00" + key + "\x00" + strconv.FormatInt(version, 10))
}

func (d delegations) Put(ctx context.Context, g state.Delegation, maxPerActor int) error {
	s := d.s
	if err := s.ready(); err != nil {
		return err
	}
	id := hex.EncodeToString(g.IDHash)
	keyID, sealed := "", []byte(nil)
	if g.Subject != nil {
		var err error
		if keyID, sealed, err = s.envelope.Seal(ctx, subjectAAD(id), g.Subject); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil) // SQLite: immediate - the count and the insert are one step
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UnixMicro()
	if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM delegations WHERE expires_at <= ?`), now); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM delegations WHERE actor_owner = ?`), g.ActorOwner).
		Scan(&n); err != nil {
		return err
	}
	if n >= maxPerActor {
		return state.ErrTooMany
	}
	if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO delegations (id_hash, actor_owner, actor_client, actor_issuer,
		user_owner, user_json, expires_at, subject_expires_at, subject_key_id, subject_sealed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`), id, g.ActorOwner, g.ActorClient, g.ActorIssuer, g.UserOwner,
		string(g.User), g.ExpiresAt.UnixMicro(), g.SubjectExpiresAt.UnixMicro(), keyID, sealed); err != nil {
		return err
	}
	return tx.Commit()
}

func (d delegations) Count(ctx context.Context, actorOwner string, now time.Time) (int, error) {
	if err := d.s.ready(); err != nil {
		return 0, err
	}
	var n int
	err := d.s.db.QueryRowContext(ctx, d.s.q(`SELECT COUNT(*) FROM delegations WHERE actor_owner = ? AND expires_at > ?`),
		actorOwner, now.UnixMicro()).Scan(&n)
	return n, err
}

func (d delegations) Get(ctx context.Context, idHash []byte, now time.Time) (*state.Delegation, error) {
	if err := d.s.ready(); err != nil {
		return nil, err
	}
	g := state.Delegation{IDHash: idHash}
	var user string
	var expires, subjectExpires int64
	err := d.s.db.QueryRowContext(ctx, d.s.q(`SELECT actor_owner, actor_client, actor_issuer, user_owner, user_json,
		expires_at, subject_expires_at FROM delegations WHERE id_hash = ? AND expires_at > ?`),
		hex.EncodeToString(idHash), now.UnixMicro()).
		Scan(&g.ActorOwner, &g.ActorClient, &g.ActorIssuer, &g.UserOwner, &user, &expires, &subjectExpires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, state.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	g.User = []byte(user)
	g.ExpiresAt, g.SubjectExpiresAt = time.UnixMicro(expires).UTC(), time.UnixMicro(subjectExpires).UTC()
	return &g, nil
}

func (d delegations) SubjectToken(ctx context.Context, idHash []byte, now time.Time) ([]byte, error) {
	if err := d.s.ready(); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idHash)
	var keyID string
	var sealed []byte
	err := d.s.db.QueryRowContext(ctx, d.s.q(`SELECT subject_key_id, subject_sealed FROM delegations
		WHERE id_hash = ? AND expires_at > ? AND subject_expires_at > ?`), id, now.UnixMicro(), now.UnixMicro()).
		Scan(&keyID, &sealed)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && sealed == nil) {
		return nil, state.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return d.s.envelope.Open(ctx, keyID, subjectAAD(id), sealed)
}

func (d delegations) Delete(ctx context.Context, idHash []byte) (bool, error) {
	if err := d.s.ready(); err != nil {
		return false, err
	}
	res, err := d.s.db.ExecContext(ctx, d.s.q(`DELETE FROM delegations WHERE id_hash = ?`), hex.EncodeToString(idHash))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (d delegations) DeleteWhere(ctx context.Context, actorClient, userOwner string) (int, error) {
	if err := d.s.ready(); err != nil {
		return 0, err
	}
	if actorClient == "" && userOwner == "" {
		return 0, errors.New("revoking grants names an actor or a user")
	}
	query, args := `DELETE FROM delegations WHERE 1 = 1`, []any{}
	if actorClient != "" {
		query, args = query+` AND actor_client = ?`, append(args, actorClient)
	}
	if userOwner != "" {
		query, args = query+` AND user_owner = ?`, append(args, userOwner)
	}
	res, err := d.s.db.ExecContext(ctx, d.s.q(query), args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (d delegations) Token(ctx context.Context, idHash []byte, key string) (*state.MintedToken, error) {
	if err := d.s.ready(); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idHash)
	t := state.MintedToken{Key: key}
	var keyID string
	var sealed []byte
	err := d.s.db.QueryRowContext(ctx, d.s.q(`SELECT version, failed, data_key_id, sealed FROM delegation_tokens
		WHERE id_hash = ? AND mint_key = ?`), id, key).Scan(&t.Version, &t.Failed, &keyID, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, state.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if sealed != nil {
		if t.Token, err = d.s.envelope.Open(ctx, keyID, tokenAAD(id, key, t.Version), sealed); err != nil {
			return nil, err
		}
	}
	return &t, nil
}

func (d delegations) PutToken(ctx context.Context, idHash []byte, t state.MintedToken) error {
	s := d.s
	if err := s.ready(); err != nil {
		return err
	}
	if t.Version < 1 {
		return state.ErrVersion
	}
	id := hex.EncodeToString(idHash)
	keyID, sealed := "", []byte(nil)
	if t.Token != nil {
		var err error
		if keyID, sealed, err = s.envelope.Seal(ctx, tokenAAD(id, t.Key, t.Version), t.Token); err != nil {
			return err
		}
	}
	if t.Version == 1 {
		_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO delegation_tokens (id_hash, mint_key, version, failed,
			data_key_id, sealed) VALUES (?, ?, 1, ?, ?, ?)`), id, t.Key, t.Failed, keyID, sealed)
		switch {
		case s.d.Unique(err):
			return state.ErrConflict
		case s.d.ForeignKey(err):
			return state.ErrNotFound // the grant is gone
		}
		return err
	}
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE delegation_tokens SET version = ?, failed = ?, data_key_id = ?,
		sealed = ? WHERE id_hash = ? AND mint_key = ? AND version = ?`), t.Version, t.Failed, keyID, sealed, id, t.Key,
		t.Version-1)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		if err == nil {
			err = state.ErrConflict
		}
		return err
	}
	return nil
}
