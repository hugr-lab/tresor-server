-- spec 004: variables and their grants, the secrets' shape: a variable is sealed as a secret's params.
CREATE TABLE variables (
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

CREATE TABLE variable_grants (
    secret    TEXT    NOT NULL REFERENCES variables (name) ON DELETE CASCADE,
    id        TEXT    NOT NULL,
    position  INTEGER NOT NULL,
    principal TEXT    NOT NULL,
    verbs     TEXT    NOT NULL,               -- JSON
    PRIMARY KEY (secret, id)
);
