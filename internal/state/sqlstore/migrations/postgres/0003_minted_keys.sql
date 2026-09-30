-- spec 002: a minted token's key is stored as its SHA-256; rows kept under the key itself (before this) would
-- never be found again. They are a cache: minted again when next used.
DELETE FROM delegation_tokens;
