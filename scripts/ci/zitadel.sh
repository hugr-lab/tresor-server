#!/usr/bin/env bash
# ZITADEL, live (spec 006, b): an instance in docker (scripts/ci/zitadel/compose.yaml), set up through its API
# with no Azure and no secret of the service's own:
#   - a project with roles, the service's OIDC app (token exchange, private key JWT, JWT access tokens with
#     roles), its key file; a downstream project;
#   - machine users alice (analysts) and admin (secrets_admin), with keys for the JWT profile grant.
# Then tresor-server (memory store) with ZITADEL as its issuer and its exchange client_auth: key_file:
#   - whoami: roles from ZITADEL's roles object;
#   - an administrator writes a token_exchange secret for the downstream project and grants it;
#   - alice reads it: a token ZITADEL minted by exchange, the service logged in with the key file;
#   - ZITADEL's refusal of a refresh by exchange is read as unsupported (zitadelcheck).
# Needs docker, go, curl, python3. ZITADEL_KEEP=1 leaves the containers up.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
dir="$root/scripts/ci/zitadel"
port="${ZITADEL_PORT:-18580}"
z="http://localhost:$port"
work="$(mktemp -d)"
export ZITADEL_PORT="$port"
server_pid=""
cleanup() {
	[ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
	if [ -z "${ZITADEL_KEEP:-}" ]; then
		docker compose -f "$dir/compose.yaml" down -v >/dev/null 2>&1 || true
		rm -rf "$dir/state"
	fi
	rm -rf "$work"
}
trap cleanup EXIT
(cd "$root" && GOWORK=off CGO_ENABLED=0 go build -o "$work/tresor-server" ./cmd/tresor-server &&
	GOWORK=off CGO_ENABLED=0 go build -o "$work/zitadelcheck" ./scripts/ci/zitadelcheck)

echo "zitadel: the instance"
rm -rf "$dir/state" && mkdir -p "$dir/state" && chmod 777 "$dir/state"
docker compose -f "$dir/compose.yaml" up -d --quiet-pull
for _ in $(seq 120); do
	[ -s "$dir/state/admin.pat" ] && curl -sf "$z/debug/healthz" >/dev/null && break
	sleep 2
done
[ -s "$dir/state/admin.pat" ] || { docker compose -f "$dir/compose.yaml" logs zitadel | tail -30; exit 1; }
pat="$(cat "$dir/state/admin.pat")"
api() { curl -sf -X "$1" "$z$2" -H "Authorization: Bearer $pat" -H "Content-Type: application/json" ${3:+-d "$3"}; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
# the API answers once the instance's first projections are done: well after the PAT and the health check
for _ in $(seq 60); do api GET /management/v1/orgs/me >/dev/null 2>&1 && break; sleep 2; done

echo "zitadel: the projects, the service's app and its key file"
project="$(api POST /management/v1/projects '{"name":"tresor","projectRoleAssertion":true}' | field '["id"]')"
downstream="$(api POST /management/v1/projects '{"name":"downstream"}' | field '["id"]')"
api POST "/management/v1/projects/${project}/roles/_bulk" \
	'{"roles":[{"key":"analysts","displayName":"analysts"},{"key":"secrets_admin","displayName":"admins"}]}' >/dev/null
app="$(api POST "/management/v1/projects/${project}/apps/oidc" '{"name":"duckdb-secrets","redirectUris":["http://localhost/cb"],
	"responseTypes":["OIDC_RESPONSE_TYPE_CODE"],"grantTypes":["OIDC_GRANT_TYPE_AUTHORIZATION_CODE","OIDC_GRANT_TYPE_TOKEN_EXCHANGE"],
	"appType":"OIDC_APP_TYPE_WEB","authMethodType":"OIDC_AUTH_METHOD_TYPE_PRIVATE_KEY_JWT","accessTokenType":"OIDC_TOKEN_TYPE_JWT",
	"accessTokenRoleAssertion":true,"idTokenRoleAssertion":true,"devMode":true}' | field '["appId"]')"
api POST "/management/v1/projects/${project}/apps/${app}/keys" '{"type":"KEY_TYPE_JSON","expirationDate":"2030-01-01T00:00:00Z"}' |
	python3 -c "import json,sys,base64; open('$work/app-key.json','wb').write(base64.b64decode(json.load(sys.stdin)['keyDetails']))"

echo "zitadel: alice (analysts) and admin (secrets_admin), with keys"
for user in alice:analysts admin:secrets_admin; do
	name="${user%%:*}" role="${user##*:}"
	id="$(api POST /management/v1/users/machine "{\"userName\":\"${name}\",\"name\":\"${name}\",\"accessTokenType\":\"ACCESS_TOKEN_TYPE_JWT\"}" | field '["userId"]')"
	api POST "/management/v1/users/${id}/grants" "{\"projectId\":\"${project}\",\"roleKeys\":[\"${role}\"]}" >/dev/null
	api POST "/management/v1/users/${id}/keys" '{"type":"KEY_TYPE_JSON","expirationDate":"2030-01-01T00:00:00Z"}' |
		python3 -c "import json,sys,base64; open('$work/${name}-key.json','wb').write(base64.b64decode(json.load(sys.stdin)['keyDetails']))"
done
alice="$("$work/zitadelcheck" token "$work/alice-key.json" "$z" "${project},${downstream}")"
admin="$("$work/zitadelcheck" token "$work/admin-key.json" "$z" "${project}")"

echo "zitadel: its refusal of a refresh by exchange, as the service reads it"
"$work/zitadelcheck" exchange "$work/app-key.json" "$z" "$alice" "${downstream}"

echo "zitadel: tresor-server with ZITADEL as its issuer, logging in with the key file"
cat >"$work/server.yaml" <<EOF
listen: 127.0.0.1:18591
public_url: http://127.0.0.1:18591
state: {kind: memory}
issuers:
  - issuer: ${z}
    audience: "${project}"
    roles_claim: "urn:zitadel:iam:org:project:${project}:roles"
    exchange: {client_auth: key_file, key_file: ${work}/app-key.json}
policy: {admins: [role:secrets_admin]}
EOF
"$work/tresor-server" -config "$work/server.yaml" >"$work/audit.log" 2>"$work/server.log" &
server_pid=$!
s=http://127.0.0.1:18591
for _ in $(seq 30); do curl -sf "$s/readyz" >/dev/null && break; sleep 1; done
call() { # token method path want [body]
	local out
	out="$(curl -s -w '\n%{http_code}' -H "Authorization: Bearer $1" -H "Content-Type: application/json" -X "$2" "$s$3" ${5:+-d "$5"})"
	[ "$(tail -1 <<<"$out")" = "$4" ] || { echo "zitadel: $2 $3: $(tail -1 <<<"$out"), want $4" >&2; head -c 300 <<<"$out" >&2; cat "$work/server.log" >&2; exit 1; }
	sed '$d' <<<"$out"
}
call "$alice" GET /v1/whoami 200 | grep -q '"role:analysts"' || { echo "zitadel: no roles from ZITADEL's object" >&2; exit 1; }
call "$admin" PUT /v1/secrets/downstream 201 "{\"type\":\"http\",\"provider\":\"token_exchange\",\"scope\":[\"https://api.example\"],\"params\":{\"audience\":\"${downstream}\"},\"redact_keys\":[]}" >/dev/null
call "$admin" PUT /v1/secrets/downstream/grants/a 200 '{"principal":"role:analysts","verbs":["use"]}' >/dev/null
call "$alice" GET /v1/secrets/downstream 200 | python3 -c 'import json,sys; t=json.load(sys.stdin)["params"]["bearer_token"]; assert len(t) > 20, "no token"'
grep -q '"kind":"mint","outcome":"ok"' "$work/audit.log" || { echo "zitadel: no mint in the audit" >&2; exit 1; }
if grep -qE "BEGIN (RSA )?PRIVATE KEY|client_assertion" "$work/server.log" "$work/audit.log"; then
	echo "zitadel: a key or an assertion reached a log" >&2
	exit 1
fi
echo "zitadel: passed - roles from ZITADEL, a token minted by exchange with the key file, no secret of the service's own"
