#!/bin/sh
# Sample secrets for the try-it stand (spec 033), made as the etl service - an administrator: an S3 secret, a
# PostgreSQL one, a variable, each granted to analysts. Fake values: they show what DuckDB is given, nothing more.
set -eu
kc=http://keycloak:8080/realms/tresor/protocol/openid-connect/token
api=http://bridge:8444
for _ in $(seq 60); do curl -sf "$api/readyz" >/dev/null && break; sleep 2; done
token=$(curl -sf "$kc" -d grant_type=client_credentials -d client_id=etl --data-urlencode "client_secret@/data/etl-secret" |
	sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$token" ] || { echo "seed: no token for etl"; exit 1; }
put() {
	code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$api$1" -H "Authorization: Bearer $token" \
		-H 'Content-Type: application/json' -d "$2")
	echo "seed: PUT $1 $code"
}
put /v1/secrets/lake '{"type":"s3","provider":"config","scope":["s3://lake"],"comment":"the data lake (sample values)",
 "params":{"key_id":"AKIAEXAMPLE","secret":{"type":"VARCHAR","value":"not-a-real-secret"},"region":"eu-central-1"},
 "redact_keys":["secret"]}'
put /v1/secrets/lake/grants/analysts '{"principal":"role:analysts","verbs":["use"]}'
put /v1/secrets/lake/grants/nodes '{"principal":"role:nodes","verbs":["use"]}'
put /v1/secrets/warehouse '{"type":"postgres","provider":"config","scope":["postgres://db.example:5432/warehouse"],
 "comment":"the warehouse (sample values)",
 "params":{"host":"db.example","port":"5432","database":"warehouse","user":"analyst",
  "password":{"type":"VARCHAR","value":"not-a-real-password"}},"redact_keys":["password"]}'
put /v1/secrets/warehouse/grants/analysts '{"principal":"role:analysts","verbs":["use"]}'
put /v1/variables/lake_bucket '{"value":"s3://lake/curated"}'
put /v1/variables/lake_bucket/grants/analysts '{"principal":"role:analysts","verbs":["use"]}'
