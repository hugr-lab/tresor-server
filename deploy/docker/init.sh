#!/bin/sh
# The try-it stand's first run (spec 033): a KEK, passwords and secrets made here, never defaults; the realm and
# the service's configuration. Later runs keep them. `init.sh passwords` shows what a person signs in with.
set -eu
umask 077
d=/data
if [ "${1:-}" = passwords ]; then
	cat "$d/passwords.txt"
	exit 0
fi
if [ -f "$d/server.yaml" ]; then
	echo "init: kept (the volume has its KEK and passwords)"
	exit 0
fi
rand() { head -c 18 /dev/urandom | base64 | tr -d '/+=' ; }
mkdir -p "$d/state"
head -c 32 /dev/urandom | base64 >"$d/kek"
kc_admin=$(rand); anna=$(rand); jonas=$(rand); etl=$(rand); node=$(rand)
printf '%s' "$kc_admin" >"$d/keycloak-admin"
printf '%s' "$etl" >"$d/etl-secret"

cat >"$d/passwords.txt" <<TXT
tresor try-it stand - made $(date -u +%Y-%m-%dT%H:%MZ); delete the volume to start over.

The console:  http://127.0.0.1:8443/ui/
  anna  / $anna   (secrets_admin: manages secrets and grants)
  jonas / $jonas   (analysts: uses what is granted)

Keycloak:     http://127.0.0.1:18480/admin/   admin / $kc_admin

Services (client_credentials at http://127.0.0.1:18480/realms/tresor/protocol/openid-connect/token):
  etl   / $etl   (an administrator, as a service)
  node  / $node   (role nodes: may act for users - policy.actors)

DuckDB:
  INSTALL tresor FROM community; LOAD tresor;
  ATTACH 'tresor:127.0.0.1:8443' AS corp (INSECURE_HTTP true);   -- a browser or device-code sign-in
TXT

audience='{"name":"audience duckdb-secrets","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.custom.audience":"duckdb-secrets","access.token.claim":"true","id.token.claim":"false"}}'
clientid='{"name":"client_id","protocol":"openid-connect","protocolMapper":"oidc-usersessionmodel-note-mapper","config":{"user.session.note":"client_id","claim.name":"client_id","jsonType.label":"String","access.token.claim":"true","id.token.claim":"false"}}'
user() { printf '{"username":"%s","enabled":true,"email":"%s@example.test","emailVerified":true,"firstName":"%s","lastName":"%s","credentials":[{"type":"password","value":"%s","temporary":false}],"realmRoles":["%s"]}' "$1" "$1" "$2" "$3" "$4" "$5"; }
service() { printf '{"clientId":"%s","publicClient":false,"secret":"%s","standardFlowEnabled":false,"serviceAccountsEnabled":true,"directAccessGrantsEnabled":false,"protocolMappers":[%s,%s]}' "$1" "$2" "$audience" "$clientid"; }
account() { printf '{"username":"service-account-%s","enabled":true,"serviceAccountClientId":"%s","realmRoles":["%s"]}' "$1" "$1" "$2"; }
cat >"$d/realm.json" <<JSON
{"realm":"tresor","enabled":true,"sslRequired":"none","accessTokenLifespan":300,"oauth2DeviceCodeLifespan":600,
 "roles":{"realm":[{"name":"secrets_admin"},{"name":"analysts"},{"name":"nodes"}]},
 "clients":[
  {"clientId":"duckdb","publicClient":true,"standardFlowEnabled":true,"directAccessGrantsEnabled":false,
   "redirectUris":["http://127.0.0.1/*","http://127.0.0.1:8443/ui/*"],"webOrigins":["http://127.0.0.1:8443"],
   "attributes":{"pkce.code.challenge.method":"S256","oauth2.device.authorization.grant.enabled":"true",
     "post.logout.redirect.uris":"http://127.0.0.1:8443/ui/*"},
   "protocolMappers":[$audience]},
  $(service etl "$etl"),
  $(service node "$node")],
 "users":[$(user anna Anna Keller "$anna" secrets_admin),$(user jonas Jonas Brandt "$jonas" analysts),
  $(account etl secrets_admin),$(account node nodes)]}
JSON

cat >"$d/server.yaml" <<YAML
# the try-it stand's configuration (spec 033) - see the docs' Configuration for every setting
listen: 127.0.0.1:8443
public_url: http://127.0.0.1:8443
state: {kind: sqlite, path: /data/state/tresor.db}
keys: {kind: local, key_file: /data/kek}
issuers:
  - issuer: http://127.0.0.1:18480/realms/tresor
    audience: duckdb-secrets
    client_id: duckdb
    scopes: [openid]
    human_flows: [authorization_code, device_code]
    service_flows: [client_credentials]
    roles_claim: realm_access.roles
    ignore_roles: [offline_access, uma_authorization, default-roles-*]
    service: {claim: client_id}
policy:
  admins: [role:secrets_admin]
  actors:
    - {principal: role:nodes, issuer: http://127.0.0.1:18480/realms/tresor, verbs: [use]}
ui: {environment: try-it}
YAML

# who reads what: the service (nonroot, 65532) its KEK, configuration and state; Keycloak (1000) the realm and
# its admin's password; the passwords and the etl secret stay root's
chown -R 65532:65532 "$d/state" "$d/kek" "$d/server.yaml"
chown 1000 "$d/keycloak-admin" "$d/realm.json"
chmod 0400 "$d/keycloak-admin" "$d/kek" "$d/realm.json"
chmod 0755 "$d"
echo "init: made - docker compose run --rm init passwords"
