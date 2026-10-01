-- spec 004: variables and their grants (PostgreSQL), the secrets' shape: a variable is sealed as a secret's
-- params.
CREATE TABLE variables (
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

CREATE TABLE variable_grants (
    secret    TEXT   NOT NULL REFERENCES variables (name) ON DELETE CASCADE,
    id        TEXT   NOT NULL,
    position  BIGINT NOT NULL,
    principal TEXT   NOT NULL,
    verbs     TEXT   NOT NULL,
    PRIMARY KEY (secret, id)
);
