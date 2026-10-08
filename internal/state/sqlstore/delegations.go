package sqlstore

import (
	"context"
	"crypto/sha256"
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

// mintKeyColumn is a minted token's key as stored: its SHA-256, hex - a key joins its audience and scope with
// a NUL, which a PostgreSQL text holds not, and may be longer than a SQL Server index key. (The AAD names the
// key itself.)
func mintKeyColumn(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func subjectAAD(idHash string) []byte { return []byte("tresor-server/delegation/1\x00" + idHash) }

func tokenAAD(idHash, key string, version int64) []byte {
	return []byte("tresor-server/minted/1\x00" + idHash + "\x00" + key + "\x00" + strconv.FormatInt(version, 10))
}

func (d delegations) Put(ctx context.Context, g state.Delegation, maxPerActor int) error {
	var err error
	for range maxAttempts {
		if err = d.put(ctx, g, maxPerActor); err == nil || !d.s.d.Retryable(err) {
			return err
		}
	}
	return err // a deadlock victim, again and again
}

func (d delegations) put(ctx context.Context, g state.Delegation, maxPerActor int) error {
	s := d.s
	if err := s.ready(); err != nil {
		return err
	}
	id := hex.EncodeToString(g.IDHash)
	keyID, sealed := "", []byte(nil)
	var err error
	if g.Subject != nil {
		if keyID, sealed, err = s.envelope.Seal(ctx, subjectAAD(id), g.Subject); err != nil {
			return err
		}
	} else if keyID, err = s.envelope.ActiveID(ctx); err != nil { // the MAC's key (spec 014), no subject sealed
		return err
	}
	stored := &delegationRow{id: id, actorOwner: g.ActorOwner, actorClient: g.ActorClient, actorIssuer: g.ActorIssuer,
		userOwner: g.UserOwner, user: string(g.User), expires: g.ExpiresAt.UnixMicro(),
		subjectExpires: g.SubjectExpiresAt.UnixMicro(), keyID: keyID, sealed: sealed}
	mac, err := s.macOf(ctx, keyID, stored.canonical)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// the count and the insert are one step: the actor's grants are locked (SQLite: its transaction is)
	if err := s.d.Lock(ctx, tx, "tresor-server/grants/"+g.ActorOwner); err != nil {
		return err
	}
	// only this actor's rows: another actor's are another lock's (Purge takes them all, on its own)
	var n int
	if err := tx.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM delegations WHERE actor_owner = ? AND expires_at > ?`),
		g.ActorOwner, time.Now().UnixMicro()).Scan(&n); err != nil {
		return err
	}
	if n >= maxPerActor {
		return state.ErrTooMany
	}
	if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO delegations (id_hash, actor_owner, actor_client, actor_issuer,
		user_owner, user_json, expires_at, subject_expires_at, subject_key_id, subject_sealed, mac)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`), id, g.ActorOwner, g.ActorClient, g.ActorIssuer, g.UserOwner,
		string(g.User), stored.expires, stored.subjectExpires, keyID, sealed, mac); err != nil {
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

// row reads a live delegation grant as stored, its MAC checked (spec 014); ErrNotFound when there is none.
func (d delegations) row(ctx context.Context, id string, now time.Time) (*delegationRow, error) {
	r := delegationRow{id: id}
	err := d.s.db.QueryRowContext(ctx, d.s.q(`SELECT actor_owner, actor_client, actor_issuer, user_owner, user_json,
		expires_at, subject_expires_at, subject_key_id, subject_sealed, mac
		FROM delegations WHERE id_hash = ? AND expires_at > ?`), id, now.UnixMicro()).
		Scan(&r.actorOwner, &r.actorClient, &r.actorIssuer, &r.userOwner, &r.user, &r.expires, &r.subjectExpires,
			&r.keyID, &r.sealed, &r.mac)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, state.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := d.s.verify(ctx, "a delegation grant", r.keyID, r.canonical, r.mac); err != nil {
		return nil, err
	}
	return &r, nil
}

func (d delegations) Get(ctx context.Context, idHash []byte, now time.Time) (*state.Delegation, error) {
	if err := d.s.ready(); err != nil {
		return nil, err
	}
	r, err := d.row(ctx, hex.EncodeToString(idHash), now)
	if err != nil {
		return nil, err
	}
	g := state.Delegation{IDHash: idHash, ActorOwner: r.actorOwner, ActorClient: r.actorClient, ActorIssuer: r.actorIssuer,
		UserOwner: r.userOwner, User: []byte(r.user), HasSubject: r.sealed != nil,
		ExpiresAt: time.UnixMicro(r.expires).UTC(), SubjectExpiresAt: time.UnixMicro(r.subjectExpires).UTC()}
	return &g, nil
}

func (d delegations) SubjectToken(ctx context.Context, idHash []byte, now time.Time) ([]byte, error) {
	if err := d.s.ready(); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idHash)
	r, err := d.row(ctx, id, now)
	if err != nil {
		return nil, err
	}
	if r.sealed == nil || r.subjectExpires <= now.UnixMicro() {
		return nil, state.ErrNotFound
	}
	return d.s.envelope.Open(ctx, r.keyID, subjectAAD(id), r.sealed)
}

func (d delegations) Purge(ctx context.Context, now time.Time) (int, error) {
	if err := d.s.ready(); err != nil {
		return 0, err
	}
	res, err := d.s.db.ExecContext(ctx, d.s.q(`DELETE FROM delegations WHERE expires_at <= ?`), now.UnixMicro())
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
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
	r := tokenRow{id: id, key: key}
	err := d.s.db.QueryRowContext(ctx, d.s.q(`SELECT version, failed, data_key_id, sealed, mac FROM delegation_tokens
		WHERE id_hash = ? AND mint_key = ?`), id, mintKeyColumn(key)).Scan(&r.version, &r.failed, &r.keyID, &r.sealed, &r.mac)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, state.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := d.s.verify(ctx, "a minted token", r.keyID, r.canonical, r.mac); err != nil {
		return nil, err
	}
	t := state.MintedToken{Key: key, Version: r.version, Failed: r.failed}
	if r.sealed != nil {
		if t.Token, err = d.s.envelope.Open(ctx, r.keyID, tokenAAD(id, key, t.Version), r.sealed); err != nil {
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
	var err error
	if t.Token != nil {
		if keyID, sealed, err = s.envelope.Seal(ctx, tokenAAD(id, t.Key, t.Version), t.Token); err != nil {
			return err
		}
	} else if keyID, err = s.envelope.ActiveID(ctx); err != nil { // the MAC's key (spec 014), nothing sealed
		return err
	}
	stored := &tokenRow{id: id, key: t.Key, version: t.Version, failed: t.Failed, keyID: keyID, sealed: sealed}
	mac, err := s.macOf(ctx, keyID, stored.canonical)
	if err != nil {
		return err
	}
	if t.Version == 1 {
		_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO delegation_tokens (id_hash, mint_key, version, failed,
			data_key_id, sealed, mac) VALUES (?, ?, 1, ?, ?, ?, ?)`), id, mintKeyColumn(t.Key), t.Failed, keyID, sealed, mac)
		switch {
		case s.d.Unique(err) || s.d.Retryable(err):
			return state.ErrConflict
		case s.d.ForeignKey(err):
			return state.ErrNotFound // the grant is gone
		}
		return err
	}
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE delegation_tokens SET version = ?, failed = ?, data_key_id = ?,
		sealed = ?, mac = ? WHERE id_hash = ? AND mint_key = ? AND version = ?`), t.Version, t.Failed, keyID, sealed, mac, id,
		mintKeyColumn(t.Key), t.Version-1)
	if s.d.Retryable(err) {
		return state.ErrConflict // nothing written: the caller reads what is there, and tries again
	}
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
