-- spec 014: a MAC on every row that says who may use what (the secrets', the variables' and their grants', the
-- delegation grants', the minted tokens'), under a data key; the installation's id, in every MAC. NULL: a row
-- written before (tresor-server mac fills it).
ALTER TABLE secrets ADD mac BYTEA NULL;
ALTER TABLE variables ADD mac BYTEA NULL;
ALTER TABLE delegations ADD mac BYTEA NULL;
ALTER TABLE delegation_tokens ADD mac BYTEA NULL;
CREATE TABLE installation (
    id       BIGINT NOT NULL PRIMARY KEY CHECK (id = 1),
    instance TEXT   NOT NULL
);
