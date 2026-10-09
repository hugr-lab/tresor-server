package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/hugr-lab/tresor-server/internal/keys"
)

// Reseal moves every secret, variable and delegation grant sealed or authenticated under another data key to
// the active one (spec 018): the material opened and sealed again with the same AAD, the MAC made anew - the
// version, the times and the ETag kept. A row moves only when its MAC verifies under its old data key (none:
// tresor-server mac first); each move is compare-and-set on the row and its MAC as read, and a row written
// meanwhile is under the active key already. Minted tokens stay: their AAD names their key, which the store keeps
// only hashed - they go with their grant. A row that cannot move is logged and counted as skipped.
func (s *Store) Reseal(ctx context.Context) (moved, skipped int, err error) {
	if err := s.ready(); err != nil {
		return 0, 0, err
	}
	active, err := s.envelope.ActiveID(ctx)
	if err != nil {
		return 0, 0, err
	}
	skip := func(what string, err error) {
		skipped++
		s.log.Warn("tresor-server reseal: a row left under its data key", "row", what, "error", err.Error())
	}
	// checked: the row's MAC verifies under its data key; an outage is no reason to skip, nor to move
	checked := func(what, keyID string, msg func(string) []byte, mac []byte) (bool, error) {
		if mac == nil {
			skip(what, errors.New("it has no MAC: tresor-server mac first"))
			return false, nil
		}
		err := s.check(ctx, keyID, msg, mac)
		if errors.Is(err, keys.ErrSealed) {
			skip(what, err)
			return false, nil
		}
		return err == nil, err
	}
	for _, st := range []*Store{s, s.vars} {
		rows, err := st.query(ctx, "")
		if err != nil {
			return moved, skipped, err
		}
		for _, r := range rows {
			if r.dataKeyID == active {
				continue
			}
			what := st.ns.entries + " " + r.sec.Name
			if ok, err := checked(what, r.dataKeyID, st.canonical(r), r.mac); !ok {
				if err != nil {
					return moved, skipped, err
				}
				continue
			}
			aad := st.paramsAAD(r.rowID, r.sec.Name, r.sec.Version)
			plain, err := st.envelope.Open(ctx, r.dataKeyID, aad, r.sealed)
			if errors.Is(err, keys.ErrSealed) {
				skip(what, err)
				continue
			}
			if err != nil {
				return moved, skipped, err
			}
			keyID, sealed, err := st.envelope.Seal(ctx, aad, plain)
			clear(plain)
			if err != nil {
				return moved, skipped, err
			}
			next := *r
			next.dataKeyID, next.sealed = keyID, sealed
			mac, err := st.macOf(ctx, keyID, st.canonical(&next))
			if err != nil {
				return moved, skipped, err
			}
			res, err := st.db.ExecContext(ctx, st.q(`UPDATE {entries} SET data_key_id = ?, sealed = ?, mac = ?
				WHERE name = ? AND version = ? AND row_id = ? AND data_key_id = ? AND mac = ?`),
				keyID, sealed, mac, r.sec.Name, r.sec.Version, r.rowID, r.dataKeyID, r.mac)
			if err != nil {
				return moved, skipped, err
			}
			if k, _ := res.RowsAffected(); k == 1 {
				moved++
			}
		}
	}

	grants, err := s.db.QueryContext(ctx, s.q(`SELECT id_hash, actor_owner, actor_client, actor_issuer, user_owner, user_json,
		expires_at, subject_expires_at, subject_key_id, subject_sealed, mac FROM delegations WHERE subject_key_id <> ?`), active)
	if err != nil {
		return moved, skipped, err
	}
	var pending []*delegationRow
	for grants.Next() {
		var r delegationRow
		if err := grants.Scan(&r.id, &r.actorOwner, &r.actorClient, &r.actorIssuer, &r.userOwner, &r.user, &r.expires,
			&r.subjectExpires, &r.keyID, &r.sealed, &r.mac); err != nil {
			grants.Close()
			return moved, skipped, err
		}
		pending = append(pending, &r)
	}
	grants.Close()
	if err := grants.Err(); err != nil {
		return moved, skipped, err
	}
	for _, r := range pending {
		if ok, err := checked("a delegation grant", r.keyID, r.canonical, r.mac); !ok {
			if err != nil {
				return moved, skipped, err
			}
			continue
		}
		old, oldMAC := r.keyID, r.mac
		r.keyID = active
		if r.sealed != nil {
			plain, err := s.envelope.Open(ctx, old, subjectAAD(r.id), r.sealed)
			if errors.Is(err, keys.ErrSealed) {
				skip("a delegation grant", err)
				continue
			}
			if err != nil {
				return moved, skipped, err
			}
			r.keyID, r.sealed, err = s.envelope.Seal(ctx, subjectAAD(r.id), plain)
			clear(plain)
			if err != nil {
				return moved, skipped, err
			}
		}
		mac, err := s.macOf(ctx, r.keyID, r.canonical)
		if err != nil {
			return moved, skipped, err
		}
		res, err := s.db.ExecContext(ctx, s.q(`UPDATE delegations SET subject_key_id = ?, subject_sealed = ?, mac = ?
			WHERE id_hash = ? AND subject_key_id = ? AND mac = ?`), r.keyID, r.sealed, mac, r.id, old, oldMAC)
		if err != nil {
			return moved, skipped, err
		}
		if k, _ := res.RowsAffected(); k == 1 {
			moved++
		}
	}
	return moved, skipped, nil
}

// DataKeysInUse names every data key a row is sealed or authenticated under (spec 018: what -retire keeps).
func (s *Store) DataKeysInUse(ctx context.Context) (map[string]bool, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT data_key_id FROM secrets UNION SELECT data_key_id FROM variables
		UNION SELECT subject_key_id FROM delegations UNION SELECT data_key_id FROM delegation_tokens`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	used := map[string]bool{}
	for rows.Next() {
		var id sql.NullString
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if id.String != "" {
			used[id.String] = true
		}
	}
	return used, rows.Err()
}

// RowsBehind counts the rows under another data key than active (spec 019), minted tokens included.
func (s *Store) RowsBehind(ctx context.Context, active string) (int, error) {
	if err := s.ready(); err != nil {
		return 0, err
	}
	var n int
	err := s.db.QueryRowContext(ctx, s.q(`SELECT
		(SELECT COUNT(*) FROM secrets WHERE data_key_id <> ?) + (SELECT COUNT(*) FROM variables WHERE data_key_id <> ?) +
		(SELECT COUNT(*) FROM delegations WHERE subject_key_id <> ? AND subject_key_id <> '') +
		(SELECT COUNT(*) FROM delegation_tokens WHERE data_key_id <> ?)`),
		active, active, active, active).Scan(&n)
	return n, err
}
