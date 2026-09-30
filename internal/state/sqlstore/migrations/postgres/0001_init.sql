-- spec 002: secrets with their grants, and the data keys that seal their params (PostgreSQL). Times are
-- microseconds since the epoch, UTC. JSON is kept as text. Material is only ever sealed.
CREATE TABLE secrets (
    name        TEXT   NOT NULL PRIMARY KEY,
    row_id      TEXT   NOT NULL,
    type        TEXT   NOT NULL,
    provider    TEXT   NOT NULL,
    scope       TEXT   NOT NULL,
    redact_keys TEXT   NOT NULL,
    comment     TEXT   NOT NULL,
    owner       TEXT   NOT NULL,
    version     BIGINT NOT NULL,
    created_at  BIGINT NOT NULL,
    updated_at  BIGINT NOT NULL,
    data_key_id TEXT   NOT NULL,
    sealed      BYTEA  NOT NULL
);

CREATE TABLE grants (
    secret    TEXT   NOT NULL REFERENCES secrets (name) ON DELETE CASCADE,
    id        TEXT   NOT NULL,
    position  BIGINT NOT NULL,
    principal TEXT   NOT NULL,
    verbs     TEXT   NOT NULL,
    PRIMARY KEY (secret, id)
);

CREATE TABLE data_keys (
    id         TEXT   NOT NULL PRIMARY KEY,
    kek_id     TEXT   NOT NULL,
    wrapped    BYTEA  NOT NULL,
    created_at BIGINT NOT NULL,
    retired_at BIGINT
);

CREATE TABLE active_data_key (
    id          BIGINT NOT NULL PRIMARY KEY CHECK (id = 1),
    data_key_id TEXT   NOT NULL REFERENCES data_keys (id),
    version     BIGINT NOT NULL
);
