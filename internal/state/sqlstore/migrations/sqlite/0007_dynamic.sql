-- spec 023: a secret with a parameter made on each read is dynamic - said by the row, so a list (which opens no
-- params) says so too. 0: written before, or static.
ALTER TABLE secrets ADD COLUMN dynamic INTEGER NOT NULL DEFAULT 0;
ALTER TABLE variables ADD COLUMN dynamic INTEGER NOT NULL DEFAULT 0;
