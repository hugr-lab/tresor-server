#!/usr/bin/env bash
# The console end to end (spec 010, d): Keycloak in docker (a realm with a public client, an administrator and an
# analyst, passwords made for this run), tresor-server with the console built (SQLite, a local KEK made for this
# run, the test host's origin allowed), the microfrontend's test host on another origin, then Playwright
# (web/console/e2e). Needs docker, go, node (npm ci done in web/console), python3, openssl.
# E2E_KEEP=1 leaves Keycloak up (its passwords were this run's and are gone: only its admin API logs are of use).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
console="$root/web/console"
kc_port="${E2E_KC_PORT:-18690}"
tresor_port="${E2E_TRESOR_PORT:-18643}"
host_port="${E2E_HOST_PORT:-18644}"
kc="http://127.0.0.1:$kc_port"
tresor="http://127.0.0.1:$tresor_port"
host="http://127.0.0.1:$host_port"
work="$(mktemp -d)"
name=tresor-e2e-kc
pids=()
cleanup() {
	for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null || true; done
	[ -z "${E2E_KEEP:-}" ] && docker rm -f "$name" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

# passwords for this run only: never printed
E2E_KC_ADMIN=admin
E2E_KC_ADMIN_PW="$(openssl rand -hex 16)"
E2E_ADMIN_PW="$(openssl rand -hex 16)"
E2E_USER_PW="$(openssl rand -hex 16)"

echo "e2e: Keycloak"
TRESOR="$tresor" HOST="$host" E2E_ADMIN_PW="$E2E_ADMIN_PW" E2E_USER_PW="$E2E_USER_PW" python3 - "$work/realm.json" <<'PY'
import json, os, sys
tresor, host = os.environ["TRESOR"], os.environ["HOST"]
user = lambda name, first, last, pw, role: {"username": name, "enabled": True, "email": f"{name}@example.test", "emailVerified": True,
    "firstName": first, "lastName": last, "credentials": [{"type": "password", "value": pw, "temporary": False}], "realmRoles": [role]}
realm = {
    "realm": "tresor", "enabled": True, "sslRequired": "none",
    "roles": {"realm": [{"name": "secrets_admin"}, {"name": "analysts"}]},
    "clients": [{
        "clientId": "tresor-console", "publicClient": True, "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
        "redirectUris": [f"{tresor}/ui/*", f"{host}/platform/*"], "webOrigins": [tresor, host],
        # 90 s tokens: the session-ended test waits for one to run out
        "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": f"{tresor}/ui/*", "access.token.lifespan": "90"},
        "protocolMappers": [{"name": "aud", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
            "config": {"included.custom.audience": "duckdb-secrets", "access.token.claim": "true", "id.token.claim": "false"}}],
    }],
    "users": [user("anna", "Anna", "Keller", os.environ["E2E_ADMIN_PW"], "secrets_admin"),
              user("jonas", "Jonas", "Brandt", os.environ["E2E_USER_PW"], "analysts")],
}
json.dump(realm, open(sys.argv[1], "w"))
PY
chmod 644 "$work/realm.json"
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -p "127.0.0.1:$kc_port:8080" \
	-e KC_BOOTSTRAP_ADMIN_USERNAME="$E2E_KC_ADMIN" -e KC_BOOTSTRAP_ADMIN_PASSWORD="$E2E_KC_ADMIN_PW" \
	-v "$work/realm.json:/opt/keycloak/data/import/realm.json:ro" \
	quay.io/keycloak/keycloak:26.4 start-dev --import-realm >/dev/null

echo "e2e: the console and the service"
(cd "$console" && npm run build >/dev/null)
(cd "$root" && GOWORK=off CGO_ENABLED=0 go build -o "$work/tresor-server" ./cmd/tresor-server)
openssl rand -base64 32 >"$work/kek" && chmod 600 "$work/kek"
cat >"$work/server.yaml" <<YAML
listen: 127.0.0.1:$tresor_port
public_url: $tresor
state: {kind: sqlite, path: $work/tresor.db}
keys: {kind: local, key_file: $work/kek}
issuers:
  - {issuer: $kc/realms/tresor, audience: duckdb-secrets, client_id: tresor-console, scopes: [openid], roles_claim: realm_access.roles}
policy: {admins: ['role:secrets_admin']}
ui: {environment: e2e, allowed_origins: ['$host']}
YAML

for _ in $(seq 90); do curl -sf "$kc/realms/tresor/.well-known/openid-configuration" >/dev/null && break; sleep 2; done
curl -sf "$kc/realms/tresor/.well-known/openid-configuration" >/dev/null || { docker logs "$name" | tail -30; exit 1; }

"$work/tresor-server" -config "$work/server.yaml" >"$work/server.log" 2>&1 &
pids+=($!)
for _ in $(seq 30); do curl -sf "$tresor/healthz" >/dev/null && break; sleep 1; done
curl -sf "$tresor/healthz" >/dev/null || { tail -30 "$work/server.log"; exit 1; }

echo "e2e: the test host"
(cd "$console" && HOST_PORT="$host_port" VITE_TRESOR_URL="$tresor" VITE_ISSUER="$kc/realms/tresor" VITE_CLIENT_ID=tresor-console \
	exec ./node_modules/.bin/vite -c vite.host.config.ts >"$work/host.log" 2>&1) &
pids+=($!)
for _ in $(seq 30); do curl -sf "$host/platform/home" >/dev/null && break; sleep 1; done
curl -sf "$host/platform/home" >/dev/null || { tail -30 "$work/host.log"; exit 1; }

echo "e2e: Playwright"
status=0
# the passwords go to Playwright only
(cd "$console" && E2E_TRESOR_URL="$tresor" E2E_KEYCLOAK_URL="$kc" E2E_HOST_URL="$host" \
	E2E_KC_ADMIN="$E2E_KC_ADMIN" E2E_KC_ADMIN_PW="$E2E_KC_ADMIN_PW" E2E_ADMIN_PW="$E2E_ADMIN_PW" E2E_USER_PW="$E2E_USER_PW" \
	npx playwright test) || status=$?
# nothing secret in the logs, checked before any is shown: the secret value written, a bearer token (a JWT),
# the KEK, a password of this run
leak=""
for log in "$work/server.log" "$work/host.log"; do
	if grep -qF -e "e2e-hunter2" -e "$E2E_ADMIN_PW" -e "$E2E_USER_PW" -e "$E2E_KC_ADMIN_PW" "$log" ||
		grep -qE 'eyJ[A-Za-z0-9_-]{8,}\.eyJ' "$log" || grep -qF -f "$work/kek" "$log"; then
		leak="$log"
	fi
done
if [ -n "$leak" ]; then
	echo "e2e: a secret value, a token, the KEK or a password reached $(basename "$leak")"; exit 1
fi
if [ "$status" -ne 0 ]; then
	echo "--- the service's log (tail)"; tail -40 "$work/server.log"
fi
exit "$status"
