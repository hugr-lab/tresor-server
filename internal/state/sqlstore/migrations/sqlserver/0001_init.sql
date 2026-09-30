-- spec 002: secrets with their grants, and the data keys that seal their params (SQL Server, Azure SQL).
-- Times are microseconds since the epoch, UTC. JSON is kept as text. Material is only ever sealed. A key or an
-- indexed text is NVARCHAR(450): an index key holds 900 bytes at most.
CREATE TABLE secrets (
    name        NVARCHAR(450)  NOT NULL PRIMARY KEY,
    row_id      NVARCHAR(64)   NOT NULL,
    type        NVARCHAR(MAX)  NOT NULL,
    provider    NVARCHAR(MAX)  NOT NULL,
    scope       NVARCHAR(MAX)  NOT NULL,
    redact_keys NVARCHAR(MAX)  NOT NULL,
    comment     NVARCHAR(MAX)  NOT NULL,
    owner       NVARCHAR(MAX)  NOT NULL,
    version     BIGINT         NOT NULL,
    created_at  BIGINT         NOT NULL,
    updated_at  BIGINT         NOT NULL,
    data_key_id NVARCHAR(64)   NOT NULL,
    sealed      VARBINARY(MAX) NOT NULL
);

CREATE TABLE grants (
    secret    NVARCHAR(450) NOT NULL REFERENCES secrets (name) ON DELETE CASCADE,
    id        NVARCHAR(400) NOT NULL,
    position  BIGINT        NOT NULL,
    principal NVARCHAR(MAX) NOT NULL,
    verbs     NVARCHAR(MAX) NOT NULL,
    PRIMARY KEY NONCLUSTERED (secret, id)     -- 1700 bytes; a clustered key holds 900
);

CREATE TABLE data_keys (
    id         NVARCHAR(64)   NOT NULL PRIMARY KEY,
    kek_id     NVARCHAR(MAX)  NOT NULL,
    wrapped    VARBINARY(MAX) NOT NULL,
    created_at BIGINT         NOT NULL,
    retired_at BIGINT
);

CREATE TABLE active_data_key (
    id          BIGINT       NOT NULL PRIMARY KEY CHECK (id = 1),
    data_key_id NVARCHAR(64) NOT NULL REFERENCES data_keys (id),
    version     BIGINT       NOT NULL
);
