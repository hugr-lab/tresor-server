-- spec 002: delegation grants and their minted tokens (PostgreSQL). A grant's id is never stored: rows are
-- keyed by its SHA-256 (hex). Its subject token and minted tokens are only ever sealed.
CREATE TABLE delegations (
    id_hash            TEXT   NOT NULL PRIMARY KEY,
    actor_owner        TEXT   NOT NULL,
    actor_client       TEXT   NOT NULL,
    actor_issuer       TEXT   NOT NULL,
    user_owner         TEXT   NOT NULL,
    user_json          TEXT   NOT NULL,
    expires_at         BIGINT NOT NULL,
    subject_expires_at BIGINT NOT NULL,
    subject_key_id     TEXT   NOT NULL,
    subject_sealed     BYTEA
);
CREATE INDEX delegations_actor ON delegations (actor_owner, expires_at);
CREATE INDEX delegations_user ON delegations (user_owner);
CREATE INDEX delegations_expiry ON delegations (expires_at);

CREATE TABLE delegation_tokens (
    id_hash     TEXT   NOT NULL REFERENCES delegations (id_hash) ON DELETE CASCADE,
    mint_key    TEXT   NOT NULL,
    version     BIGINT NOT NULL,
    failed      TEXT   NOT NULL,
    data_key_id TEXT   NOT NULL,
    sealed      BYTEA,
    PRIMARY KEY (id_hash, mint_key)
);
