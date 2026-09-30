-- spec 002: delegation grants and their minted tokens, for every replica to honour. A grant's id is never
-- stored: rows are keyed by its SHA-256 (hex). Its subject token and minted tokens are only ever sealed.
CREATE TABLE delegations (
    id_hash            TEXT    NOT NULL PRIMARY KEY,
    actor_owner        TEXT    NOT NULL,
    actor_client       TEXT    NOT NULL,
    actor_issuer       TEXT    NOT NULL,
    user_owner         TEXT    NOT NULL,
    user_json          TEXT    NOT NULL,
    expires_at         INTEGER NOT NULL,
    subject_expires_at INTEGER NOT NULL,
    subject_key_id     TEXT    NOT NULL,       -- '' when no subject token is kept
    subject_sealed     BLOB                    -- NULL when no subject token is kept
);
CREATE INDEX delegations_actor ON delegations (actor_owner, expires_at);
CREATE INDEX delegations_user ON delegations (user_owner);
CREATE INDEX delegations_expiry ON delegations (expires_at);

CREATE TABLE delegation_tokens (
    id_hash     TEXT    NOT NULL REFERENCES delegations (id_hash) ON DELETE CASCADE,
    mint_key    TEXT    NOT NULL,
    version     INTEGER NOT NULL,              -- compare-and-set: refresh tokens rotate
    failed      TEXT    NOT NULL,              -- why minting failed for good; '' when a token is kept
    data_key_id TEXT    NOT NULL,
    sealed      BLOB,                          -- the token (JSON); NULL when minting failed
    PRIMARY KEY (id_hash, mint_key)
);
