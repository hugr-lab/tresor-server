-- spec 002: delegation grants and their minted tokens (SQL Server, Azure SQL). A grant's id is never stored:
-- rows are keyed by its SHA-256 (hex). Its subject token and minted tokens are only ever sealed.
CREATE TABLE delegations (
    id_hash            NVARCHAR(64)   NOT NULL PRIMARY KEY,
    actor_owner        NVARCHAR(400)  NOT NULL,
    actor_client       NVARCHAR(400)  NOT NULL,
    actor_issuer       NVARCHAR(MAX)  NOT NULL,
    user_owner         NVARCHAR(400)  NOT NULL,
    user_json          NVARCHAR(MAX)  NOT NULL,
    expires_at         BIGINT         NOT NULL,
    subject_expires_at BIGINT         NOT NULL,
    subject_key_id     NVARCHAR(64)   NOT NULL,
    subject_sealed     VARBINARY(MAX)
);
CREATE INDEX delegations_actor ON delegations (actor_owner, expires_at);
CREATE INDEX delegations_user ON delegations (user_owner);
CREATE INDEX delegations_client ON delegations (actor_client);
CREATE INDEX delegations_expiry ON delegations (expires_at);

CREATE TABLE delegation_tokens (
    id_hash     NVARCHAR(64)   NOT NULL REFERENCES delegations (id_hash) ON DELETE CASCADE,
    mint_key    NVARCHAR(64)   NOT NULL,     -- the key's SHA-256, hex
    version     BIGINT         NOT NULL,
    failed      NVARCHAR(MAX)  NOT NULL,
    data_key_id NVARCHAR(64)   NOT NULL,
    sealed      VARBINARY(MAX),
    PRIMARY KEY (id_hash, mint_key)
);
