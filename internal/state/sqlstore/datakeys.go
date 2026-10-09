package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/hugr-lab/tresor-server/internal/keys"
)

// dataKeys is the store's keys.DataKeyStore: the wrapped data keys, and the active one's slot.
type dataKeys struct{ s *Store }

func (k dataKeys) Get(ctx context.Context, id string) (keys.DataKey, error) {
	var dk keys.DataKey
	var created int64
	err := k.s.db.QueryRowContext(ctx, k.s.q(`SELECT id, kek_id, wrapped, tag, created_at FROM data_keys WHERE id = ?`), id).
		Scan(&dk.ID, &dk.KEKID, &dk.Wrapped, &dk.Tag, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return keys.DataKey{}, keys.ErrNoDataKey
	}
	dk.CreatedAt = time.UnixMicro(created).UTC()
	return dk, err
}

func (k dataKeys) Active(ctx context.Context) (keys.DataKey, int64, error) {
	var id string
	var slot int64
	err := k.s.db.QueryRowContext(ctx, k.s.q(`SELECT data_key_id, version FROM active_data_key WHERE id = 1`)).
		Scan(&id, &slot)
	if errors.Is(err, sql.ErrNoRows) {
		return keys.DataKey{}, 0, keys.ErrNoDataKey
	}
	if err != nil {
		return keys.DataKey{}, 0, err
	}
	dk, err := k.Get(ctx, id)
	return dk, slot, err
}

// Activate stores dk and makes it active, compare-and-set on the slot: the first activation inserts the
// slot (a unique violation: another replica's came first), a later one updates it at its version.
func (k dataKeys) Activate(ctx context.Context, dk keys.DataKey, slot int64) error {
	tx, err := k.s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, k.s.q(`INSERT INTO data_keys (id, kek_id, wrapped, tag, created_at) VALUES (?, ?, ?, ?, ?)`),
		dk.ID, dk.KEKID, dk.Wrapped, dk.Tag, dk.CreatedAt.UnixMicro()); err != nil {
		return err
	}
	if slot == 0 {
		_, err := tx.ExecContext(ctx, k.s.q(`INSERT INTO active_data_key (id, data_key_id, version) VALUES (1, ?, 1)`), dk.ID)
		if k.s.d.Unique(err) || k.s.d.Retryable(err) {
			return keys.ErrKeyRace
		}
		if err != nil {
			return err
		}
	} else {
		res, err := tx.ExecContext(ctx, k.s.q(`UPDATE active_data_key SET data_key_id = ?, version = version + 1
			WHERE id = 1 AND version = ?`), dk.ID, slot)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			if err == nil {
				err = keys.ErrKeyRace
			}
			return err
		}
	}
	return tx.Commit()
}

func (k dataKeys) List(ctx context.Context) ([]keys.DataKey, error) {
	rows, err := k.s.db.QueryContext(ctx, k.s.q(`SELECT id, kek_id, wrapped, tag, created_at FROM data_keys ORDER BY created_at`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []keys.DataKey
	for rows.Next() {
		var dk keys.DataKey
		var created int64
		if err := rows.Scan(&dk.ID, &dk.KEKID, &dk.Wrapped, &dk.Tag, &created); err != nil {
			return nil, err
		}
		dk.CreatedAt = time.UnixMicro(created).UTC()
		out = append(out, dk)
	}
	return out, rows.Err()
}

func (k dataKeys) Rewrapped(ctx context.Context, id, fromKEKID string, wrapped []byte, kekID string, tag []byte) (bool, error) {
	res, err := k.s.db.ExecContext(ctx, k.s.q(`UPDATE data_keys SET kek_id = ?, wrapped = ?, tag = ? WHERE id = ? AND kek_id = ?`),
		kekID, wrapped, tag, id, fromKEKID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// Delete removes a data key (spec 018), never the active one (the slot's foreign key keeps it too).
func (k dataKeys) Delete(ctx context.Context, id string) (bool, error) {
	res, err := k.s.db.ExecContext(ctx, k.s.q(`DELETE FROM data_keys WHERE id = ?
		AND NOT EXISTS (SELECT 1 FROM active_data_key WHERE data_key_id = ?)`), id, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
