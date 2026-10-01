-- spec 004: variables and their grants (SQL Server, Azure SQL), the secrets' shape: a variable is sealed as a
-- secret's params.
CREATE TABLE variables (
    name        NVARCHAR(450)  COLLATE Latin1_General_100_BIN2 NOT NULL PRIMARY KEY,
    row_id      NVARCHAR(64)   COLLATE Latin1_General_100_BIN2 NOT NULL,
    type        NVARCHAR(MAX)  NOT NULL,
    provider    NVARCHAR(MAX)  NOT NULL,
    scope       NVARCHAR(MAX)  NOT NULL,
    redact_keys NVARCHAR(MAX)  NOT NULL,
    comment     NVARCHAR(MAX)  NOT NULL,
    owner       NVARCHAR(MAX)  NOT NULL,
    version     BIGINT         NOT NULL,
    created_at  BIGINT         NOT NULL,
    updated_at  BIGINT         NOT NULL,
    data_key_id NVARCHAR(64)   COLLATE Latin1_General_100_BIN2 NOT NULL,
    sealed      VARBINARY(MAX) NOT NULL
);

CREATE TABLE variable_grants (
    secret    NVARCHAR(450) COLLATE Latin1_General_100_BIN2 NOT NULL REFERENCES variables (name) ON DELETE CASCADE,
    id        NVARCHAR(400) COLLATE Latin1_General_100_BIN2 NOT NULL,
    position  BIGINT        NOT NULL,
    principal NVARCHAR(MAX) NOT NULL,
    verbs     NVARCHAR(MAX) NOT NULL,
    PRIMARY KEY NONCLUSTERED (secret, id)     -- 1700 bytes; a clustered key holds 900
);
