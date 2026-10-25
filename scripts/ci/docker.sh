#!/usr/bin/env bash
# The Docker recipes (spec 033): the try-it stand up from a local build - ready, seeded, a service reads a granted
# secret through it, down; the one-host recipe on localhost - Caddy's TLS (its own CA) in front of the service.
# Needs docker (compose), curl, python3. Nothing it makes is printed.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root/deploy/docker"
export TRESOR_IMAGE="${TRESOR_IMAGE:-tresor-server:ci}"
[ -n "${DOCKER_SKIP_BUILD:-}" ] || docker build -q -t "$TRESOR_IMAGE" "$root" >/dev/null
cleanup() {
	docker compose --profile seed down -v >/dev/null 2>&1 || true
	TRESOR_DOMAIN=localhost docker compose -f compose.host.yaml down -v >/dev/null 2>&1 || true
	rm -rf host/secrets host/server.yaml
}
trap cleanup EXIT

echo "docker: the try-it stand"
docker compose up -d >/dev/null 2>&1
for _ in $(seq 90); do curl -sf http://127.0.0.1:8443/readyz >/dev/null && break; sleep 2; done
curl -sf http://127.0.0.1:8443/readyz >/dev/null || { docker compose logs --tail 30; exit 1; }
docker compose --profile seed up seed 2>&1 | grep "seed: PUT" | grep -v " 20[01]$" && { echo "docker: the seed failed"; exit 1; }
node="$(docker compose run --rm -q init passwords | awk '/^  node /{print $3}')"
token="$(curl -sf http://127.0.0.1:18480/realms/tresor/protocol/openid-connect/token -d grant_type=client_credentials \
	-d client_id=node --data-urlencode "client_secret=$node" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
unset node
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" http://127.0.0.1:8443/v1/secrets/lake)"
[ "$code" = 200 ] || { echo "docker: the node read lake: $code"; exit 1; }
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" http://127.0.0.1:8443/v1/secrets/warehouse)"
[ "$code" = 404 ] || { echo "docker: the node read warehouse, granted only to analysts: $code"; exit 1; }
unset token
curl -sf -o /dev/null http://127.0.0.1:8443/ui/ || { echo "docker: no console"; exit 1; }
docker compose --profile seed down -v >/dev/null 2>&1
echo "docker: the try-it stand: ready, seeded, a node reads what it is granted, the console answers"

echo "docker: the one-host recipe (localhost)"
mkdir -m 700 -p host/secrets
openssl rand -base64 32 >host/secrets/kek && chmod 644 host/secrets/kek
sed 's#https://secrets.example.com#https://localhost#' host/server.example.yaml >host/server.yaml
TRESOR_DOMAIN=localhost docker compose -f compose.host.yaml up -d >/dev/null 2>&1
for _ in $(seq 60); do curl -sfk https://localhost/healthz >/dev/null && break; sleep 2; done
curl -sfk https://localhost/.well-known/duckdb-secrets | python3 -c '
import json,sys; d=json.load(sys.stdin); assert d["api"] == "https://localhost", d["api"]' ||
	{ TRESOR_DOMAIN=localhost docker compose -f compose.host.yaml logs --tail 30; exit 1; }
echo "docker: the one-host recipe: TLS at Caddy, the service behind it (tls.offload)"
