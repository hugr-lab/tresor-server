-- spec 014: a MAC on every row that says who may use what (the secrets', the variables' and their grants', the
-- delegation grants', the minted tokens'), under a data key; the installation's id, in every MAC. NULL: a row
-- written before (tresor-server mac fills it).
ALTER TABLE secrets ADD mac VARBINARY(64) NULL;
ALTER TABLE variables ADD mac VARBINARY(64) NULL;
ALTER TABLE delegations ADD mac VARBINARY(64) NULL;
ALTER TABLE delegation_tokens ADD mac VARBINARY(64) NULL;
CREATE TABLE installation (
    id       INT          NOT NULL PRIMARY KEY CHECK (id = 1),
    instance NVARCHAR(64) NOT NULL
);
-- the installation's id: made once, here; a store never makes it again (a missing row is an error, not a new id)
INSERT INTO installation (id, instance) VALUES (1, LOWER(REPLACE(CONVERT(NVARCHAR(36), NEWID()), '-', '')));
