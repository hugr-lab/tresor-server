-- spec 002: secrets with their grants, and the data keys that seal their params. (SQLite's lease table is
-- made before the migrations: a replica holds the lease before it migrates.)
-- Times are microseconds since the epoch, UTC. JSON is kept as text. Material is only ever sealed.
CREATE TABLE secrets (
    name        TEXT    NOT NULL PRIMARY KEY,
    row_id      TEXT    NOT NULL,             -- random per create: in the params' AAD
    type        TEXT    NOT NULL,
    provider    TEXT    NOT NULL,
    scope       TEXT    NOT NULL,             -- JSON
    redact_keys TEXT    NOT NULL,             -- JSON
    comment     TEXT    NOT NULL,
    owner       TEXT    NOT NULL,
    version     INTEGER NOT NULL,             -- the protocol's; every write is compare-and-set on it
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    data_key_id TEXT    NOT NULL,
    sealed      BLOB    NOT NULL              -- the params, AES-256-GCM under the data key
);

CREATE TABLE grants (
    secret    TEXT    NOT NULL REFERENCES secrets (name) ON DELETE CASCADE,
    id        TEXT    NOT NULL,
    position  INTEGER NOT NULL,
    principal TEXT    NOT NULL,
    verbs     TEXT    NOT NULL,               -- JSON
    PRIMARY KEY (secret, id)
);

CREATE TABLE data_keys (
    id         TEXT    NOT NULL PRIMARY KEY,
    kek_id     TEXT    NOT NULL,
    wrapped    BLOB    NOT NULL,
    created_at INTEGER NOT NULL,
    retired_at INTEGER                        -- rewrapped under a newer KEK version, or dropped (later)
);

CREATE TABLE active_data_key (
    id          INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    data_key_id TEXT    NOT NULL REFERENCES data_keys (id),
    version     INTEGER NOT NULL
);
