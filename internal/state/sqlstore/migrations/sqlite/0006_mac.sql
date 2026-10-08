-- spec 014: a MAC on every row that says who may use what (the secrets', the variables' and their grants', the
-- delegation grants', the minted tokens'), under a data key; the installation's id, in every MAC. NULL: a row
-- written before (tresor-server mac fills it).
ALTER TABLE secrets ADD COLUMN mac BLOB NULL;
ALTER TABLE variables ADD COLUMN mac BLOB NULL;
ALTER TABLE delegations ADD COLUMN mac BLOB NULL;
ALTER TABLE delegation_tokens ADD COLUMN mac BLOB NULL;
CREATE TABLE installation (
    id       INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    instance TEXT    NOT NULL
);
-- the installation's id: made once, here; a store never makes it again (a missing row is an error, not a new id)
INSERT INTO installation (id, instance) VALUES (1, lower(hex(randomblob(16))));
