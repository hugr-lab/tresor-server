#!/usr/bin/env bash
# SPIRE as an issuer, live (spec 038): a SPIRE trust domain whose JWT-SVIDs carry iss - the https URL of a
# Cloudflare quick tunnel to SPIRE's OIDC discovery - and are RS256; a tresor-server on this machine trusting it
# directly, roles by role_rules; Entra's workload identity federation taking the same SVID. Nothing printed holds a
# token; the tunnel publishes only the discovery document and the public keys.
#
#   scripts/dev/spire_live.sh up            SPIRE, the tunnel, the service (127.0.0.1:18543)
#   scripts/dev/spire_live.sh check         SVIDs to the service: admin creates and grants, a node reads, an intruder not
#   scripts/dev/spire_live.sh entra-up      a federated credential on the node app (ENTRA_* from tresor's .env)
#   scripts/dev/spire_live.sh check-entra   the node's SVID for an Entra token (jwt-bearer), that token to the service
#   scripts/dev/spire_live.sh entra-down    the federated credential removed
#   scripts/dev/spire_live.sh down          everything stopped, the trust domain forgotten
#
# Needs docker (compose), cloudflared, go, curl, python3, openssl.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
run="${SPIRE_RUN:-$root/design/spire-live}"
export SPIRE_RUN="$run"
port="${SPIRE_OIDC_PORT:-18456}"
svc_port="${TRESOR_PORT:-18543}"
td="spiffe://tresor.example"
agent_id="$td/agent/live"
compose=(docker compose -p tresor-spire -f "$here/spire/docker-compose.yml")
fic=tresor-spire-live
server_cli() { "${compose[@]}" exec -T spire-server /opt/spire/bin/spire-server "$@" -socketPath /run/spire/sockets/server/api.sock; }
svid() { # $1 audience -> a JWT-SVID for the uid-0 workload, on stdout only (callers pipe it, never print it)
	"${compose[@]}" exec -T spire-agent /opt/spire/bin/spire-agent api fetch jwt -audience "$1" \
		-spiffeID "$2" -socketPath /run/spire/sockets/agent/api.sock </dev/null 2>/dev/null |
		awk 'f && NF {print $1; exit} /^token\(/ {f=1}'
}
wait_for() { local what="$1"; shift; for _ in $(seq 90); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; echo "spire_live: $what did not come up" >&2; return 1; }

up() {
	mkdir -p "$run" && chmod 700 "$run"
	if ! [ -f "$run/tunnel.pid" ] || ! kill -0 "$(cat "$run/tunnel.pid")" 2>/dev/null; then
		cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:$port" >"$run/tunnel.log" 2>&1 &
		echo $! >"$run/tunnel.pid"
		for _ in $(seq 60); do grep -qo 'https://[a-z0-9-]*\.trycloudflare\.com' "$run/tunnel.log" && break; sleep 1; done
	fi
	issuer="$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$run/tunnel.log" | head -1)"
	[ -n "$issuer" ] || { echo "spire_live: no tunnel URL" >&2; exit 1; }
	echo "$issuer" >"$run/issuer"
	cat >"$run/server.conf" <<CONF
# spec 038's live check: SVIDs with iss (the tunnel), RS256 (Entra takes no ES256). Test only.
server {
    bind_address = "0.0.0.0"
    bind_port = "8081"
    trust_domain = "tresor.example"
    data_dir = "/run/spire/data"
    socket_path = "/run/spire/sockets/server/api.sock"
    log_level = "INFO"
    ca_ttl = "24h"
    ca_key_type = "rsa-2048"
    jwt_key_type = "rsa-2048"
    jwt_issuer = "$issuer"
    default_jwt_svid_ttl = "5m"
}
plugins {
    DataStore "sql" { plugin_data { database_type = "sqlite3" connection_string = "/run/spire/data/datastore.sqlite3" } }
    NodeAttestor "join_token" { plugin_data {} }
    KeyManager "memory" { plugin_data {} }
}
CONF
	cat >"$run/oidc.conf" <<CONF
# SPIRE's OIDC discovery behind the tunnel (spec 038): the issuer and the RS256 keys, use=sig (Entra wants it).
log_level = "INFO"
domains = ["${issuer#https://}", "127.0.0.1", "localhost"]
insecure_addr = ":8008"
allow_insecure_scheme = true
set_key_use = true
jwt_issuer = "$issuer"
server_api { address = "unix:///run/spire/sockets/server/api.sock" }
CONF
	"${compose[@]}" up -d spire-server
	wait_for "the SPIRE server" server_cli healthcheck
	if ! "${compose[@]}" ps --status running spire-agent | grep -q spire-agent; then
		local token
		token="$(server_cli token generate -spiffeID "$agent_id" | awk '/^Token:/ {print $2}')"
		SPIRE_JOIN_TOKEN="$token" "${compose[@]}" up -d spire-agent spire-oidc
	fi
	for id in hugr/node/group-a hugr/admin intruder; do
		server_cli entry create -parentID "$agent_id" -spiffeID "$td/$id" -selector unix:uid:0 >/dev/null 2>&1 || true
	done
	wait_for "the discovery behind the tunnel" curl -sf "$issuer/.well-known/openid-configuration"
	echo "spire_live: discovery at the tunnel; keys: $(curl -s "$issuer/keys" | python3 -c 'import json,sys; print([(k["kty"],k.get("alg"),k.get("use")) for k in json.load(sys.stdin)["keys"]])')"

	[ -f "$run/kek" ] || (umask 077; openssl rand -base64 32 >"$run/kek")
	(cd "$root" && GOWORK=off CGO_ENABLED=0 go build -o "$run/tresor-server" ./cmd/tresor-server)
	cat >"$run/tresor.yaml" <<YAML
listen: 127.0.0.1:$svc_port
public_url: http://127.0.0.1:$svc_port
state: {kind: sqlite, path: $run/tresor.db}
keys: {kind: local, key_file: $run/kek}
issuers:
  - issuer: $issuer
    audience: duckdb-secrets
    service: {claim: sub, client_claim: sub}
    role_rules:
      - {subject: '$td/hugr/node/*', roles: [nodes]}
      - {subject: '$td/hugr/admin', roles: [secrets_admin]}
${ENTRA_ISSUER_YAML:-}
policy:
  admins: [role:secrets_admin]
YAML
	[ -f "$run/tresor.pid" ] && kill "$(cat "$run/tresor.pid")" 2>/dev/null || true
	"$run/tresor-server" -config "$run/tresor.yaml" >"$run/tresor.log" 2>&1 &
	echo $! >"$run/tresor.pid"
	wait_for "the service" curl -sf "http://127.0.0.1:$svc_port/readyz"
	echo "spire_live: up - $(curl -s "http://127.0.0.1:$svc_port/readyz")"
}

call() { # $1 method, $2 path, $3 SPIFFE ID path; body on stdin -> the HTTP status
	local tok
	tok="$(svid duckdb-secrets "$td/$3")"
	[ -n "$tok" ] || { echo "no-svid"; return; }
	# the token as a header from its own descriptor (never on the command line), the body from stdin
	curl -s -o "$run/last" -w '%{http_code}' -X "$1" -H @<(printf 'Authorization: Bearer %s' "$tok") \
		-H 'Content-Type: application/json' --data-binary @- "http://127.0.0.1:$svc_port$2"
}

check() {
	local s
	s="$(echo -n | call GET /v1/whoami hugr/node/group-a)"
	echo "spire_live: node whoami $s: $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("subject"), d.get("roles"))' "$run/last")"
	s="$(echo '{"type":"s3","provider":"config","scope":["s3://lake"],"params":{"key_id":"AKIA","secret":{"type":"VARCHAR","value":"not-real"}},"redact_keys":["secret"]}' | call PUT /v1/secrets/lake hugr/admin)"
	echo "spire_live: admin creates lake: $s"
	s="$(echo '{"principal":"role:nodes","verbs":["use"]}' | call PUT /v1/secrets/lake/grants/nodes hugr/admin)"
	echo "spire_live: admin grants role:nodes: $s"
	s="$(echo -n | call GET /v1/secrets/lake hugr/node/group-a)"
	echo "spire_live: the node reads lake: $s"
	s="$(echo -n | call GET /v1/secrets/lake intruder)"
	echo "spire_live: an attested intruder (no rule) reads lake: $s"
	# an SVID made for another audience
	local other
	other="$(svid other-service "$td/hugr/node/group-a")"
	s="$(printf 'Authorization: Bearer %s' "$other" | curl -s -o /dev/null -w '%{http_code}' -H @- "http://127.0.0.1:$svc_port/v1/whoami")"
	echo "spire_live: an SVID for another audience: $s"
}

entra() { set -a; . "${TRESOR_ENV:-$HOME/projects/hugr-lab/tresor/.env}"; set +a; }

entra_up() {
	entra
	local issuer
	issuer="$(cat "$run/issuer")"
	az ad app federated-credential create --id "$ENTRA_NODE_CLIENT_ID" -o none --parameters "{\"name\":\"$fic\",
		\"issuer\":\"$issuer\",\"subject\":\"$td/hugr/node/group-a\",\"audiences\":[\"api://AzureADTokenExchange\"],
		\"description\":\"tresor-server spec 038 live check (scripts/dev/spire_live.sh)\"}"
	touch "$run/entra-credential" # down removes it, should entra-down be forgotten
	echo "spire_live: Entra trusts $td/hugr/node/group-a from the tunnel's issuer (on the node app)"
}

check_entra() {
	entra
	local tok answer
	tok="$(svid api://AzureADTokenExchange "$td/hugr/node/group-a")"
	answer="$(printf '%s' "$tok" | curl -s -X POST "https://login.microsoftonline.com/$ENTRA_TENANT/oauth2/v2.0/token" \
		-d grant_type=client_credentials -d "client_id=$ENTRA_NODE_CLIENT_ID" \
		-d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
		--data-urlencode "client_assertion@-" --data-urlencode "scope=$ENTRA_API_URI/.default")"
	echo "$answer" | python3 -c '
import base64,json,sys
d = json.load(sys.stdin)
t = d.get("access_token")
if not t: print("spire_live: Entra refused:", d.get("error"), (d.get("error_description") or "").split("\n")[0][:200]); sys.exit(1)
s = t.split(".")[1]; s += "=" * (-len(s) % 4); c = json.loads(base64.urlsafe_b64decode(s))
print("spire_live: Entra issued a token: roles", c.get("roles"), "idtyp", c.get("idtyp"), "for the API", c.get("aud") is not None)'
	if [ -n "${ENTRA_ISSUER_YAML:-}" ]; then
		local et
		et="$(echo "$answer" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
		printf 'Authorization: Bearer %s' "$et" | curl -s -o "$run/last" -w 'spire_live: the Entra token at the service: %{http_code}\n' -H @- "http://127.0.0.1:$svc_port/v1/whoami"
		python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("spire_live:", d.get("roles"))' "$run/last"
	fi
}

entra_down() {
	# the node app must not keep trusting a tunnel hostname that can be handed out again
	[ -f "$run/entra-credential" ] && entra_down
	entra
	az ad app federated-credential delete --id "$ENTRA_NODE_CLIENT_ID" --federated-credential-id "$fic" -o none 2>/dev/null || true
	rm -f "$run/entra-credential"
	echo "spire_live: the federated credential removed"
}

down() {
	for p in tresor tunnel; do [ -f "$run/$p.pid" ] && kill "$(cat "$run/$p.pid")" 2>/dev/null || true; done
	"${compose[@]}" down -v >/dev/null 2>&1 || true
	rm -rf "$run"
	echo "spire_live: down"
}

case "${1:-}" in
up) up ;; check) check ;; entra-up) entra_up ;; check-entra) check_entra ;; entra-down) entra_down ;; down) down ;;
*) echo "usage: $0 up|check|entra-up|check-entra|entra-down|down" >&2; exit 2 ;;
esac
