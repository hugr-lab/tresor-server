#!/usr/bin/env bash
# Snowflake per user, live (spec 032): a person's own token for Snowflake's Horizon catalog, minted by Entra's
# On-Behalf-Of (mint+exchange) - Snowflake's External OAuth takes it, the role from its scope. Run against a
# tresor-server on this machine; nothing is printed of a token, a secret or the tenant's ids.
#
#   set -a; . ~/projects/hugr-lab/tresor/.env; set +a
#   scripts/dev/snowflake_live.sh up      # Entra: the Snowflake resource app, its scope consented for duckdb-secrets,
#                                         # a certificate on duckdb-secrets for this machine's OBO; writes
#                                         # design/snowflake/entra.sql (Snowflake's side, for an ACCOUNTADMIN) and
#                                         # design/snowflake/entra-issuer.yaml (the issuer for server.yaml)
#   scripts/dev/snowflake_live.sh check   # a person signs in (device code); the service mints their Snowflake token;
#                                         # Horizon lists the namespaces and loads the table with vended credentials
#   scripts/dev/snowflake_live.sh down    # Entra back as it was (and design/snowflake/teardown.sql in Snowflake)
#
# ENTRA_TENANT, ENTRA_API_CLIENT_ID, ENTRA_API_URI, ENTRA_PEOPLE_CLIENT_ID; SNOWFLAKE_HOST (<org>-<account>.snowflakecomputing.com);
# TRESOR_URL (http://127.0.0.1:8543).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
dir="$root/design/snowflake"
app_name=tresor-snowflake
role=TRESOR_READER
cert_name=tresor-snowflake-live
for name in ENTRA_TENANT ENTRA_API_CLIENT_ID ENTRA_API_URI ENTRA_PEOPLE_CLIENT_ID SNOWFLAKE_HOST; do
	[ -n "${!name:-}" ] || { echo "snowflake_live: $name is not set" >&2; exit 1; }
done
login="https://login.microsoftonline.com/$ENTRA_TENANT"
tresor="${TRESOR_URL:-http://127.0.0.1:8543}"
resource() { az ad app list --display-name "$app_name" --query '[0].appId' -o tsv; }

up() {
	local app scope_id sp_api sp_res upn thumb
	mkdir -p "$dir"
	echo "snowflake_live: the Snowflake resource ($app_name): v1 tokens, one delegated scope session:role:$role"
	app="$(resource)"
	if [ -z "$app" ]; then
		app="$(az ad app create --display-name "$app_name" --sign-in-audience AzureADMyOrg --query appId -o tsv)"
		az ad sp create --id "$app" -o none
	fi
	scope_id="$(az ad app show --id "$app" --query "api.oauth2PermissionScopes[?value=='session:role:$role'].id | [0]" -o tsv)"
	if [ -z "$scope_id" ]; then
		scope_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
		az ad app update --id "$app" --identifier-uris "api://$app" -o none
		# v1 access tokens (Snowflake's Azure guide): iss sts.windows.net, aud the identifier URI, upn
		az ad app update --id "$app" --set "api={\"requestedAccessTokenVersion\":null,\"oauth2PermissionScopes\":[{\"id\":\"$scope_id\",\"value\":\"session:role:$role\",\"type\":\"User\",\"isEnabled\":true,\"adminConsentDisplayName\":\"Snowflake as $role\",\"adminConsentDescription\":\"tresor-server's Snowflake live check\",\"userConsentDisplayName\":\"Snowflake as $role\",\"userConsentDescription\":\"tresor-server's Snowflake live check\"}]}" -o none
	fi

	echo "snowflake_live: duckdb-secrets may call it on behalf of users (admin consent)"
	az ad app permission add --id "$ENTRA_API_CLIENT_ID" --api "$app" --api-permissions "$scope_id=Scope" -o none 2>/dev/null || true
	sp_api="$(az ad sp show --id "$ENTRA_API_CLIENT_ID" --query id -o tsv)"
	sp_res="$(az ad sp show --id "$app" --query id -o tsv)"
	for _ in $(seq 12); do
		az ad app permission admin-consent --id "$ENTRA_API_CLIENT_ID" -o none 2>/dev/null || true
		[ "$(az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/$sp_api/oauth2PermissionGrants" \
			--query "length(value[?resourceId=='$sp_res'])" -o tsv)" -gt 0 ] && break
		az rest --method post --url https://graph.microsoft.com/v1.0/oauth2PermissionGrants --headers Content-Type=application/json \
			--body "{\"clientId\":\"$sp_api\",\"consentType\":\"AllPrincipals\",\"resourceId\":\"$sp_res\",\"scope\":\"session:role:$role\"}" \
			-o none 2>/dev/null || true
		sleep 10
	done

	echo "snowflake_live: a certificate on duckdb-secrets - this machine's service authenticates its OBO requests"
	if [ ! -f "$dir/obo.pem" ]; then
		(umask 077; openssl req -x509 -newkey rsa:2048 -nodes -days 3 -subj "/CN=$cert_name" \
			-keyout "$dir/obo.key" -out "$dir/obo.crt" 2>/dev/null; cat "$dir/obo.key" "$dir/obo.crt" >"$dir/obo.pem")
		az ad app credential reset --id "$ENTRA_API_CLIENT_ID" --cert "@$dir/obo.crt" --append -o none 2>/dev/null
	fi
	thumb="$(openssl x509 -in "$dir/obo.crt" -outform DER | openssl dgst -sha1 -binary | base64 | tr '+/' '-_' | tr -d '=')"

	upn="$(az ad signed-in-user show --query userPrincipalName -o tsv)"
	cat >"$dir/entra.sql" <<SQL
-- tresor-server spec 032, per user: run as ACCOUNTADMIN after setup.sql. Entra's tokens for $app_name, the user
-- by upn, the role from the token's scope.
USE ROLE ACCOUNTADMIN;
CREATE OR REPLACE SECURITY INTEGRATION TRESOR_ENTRA TYPE = EXTERNAL_OAUTH ENABLED = TRUE
  EXTERNAL_OAUTH_TYPE = AZURE
  EXTERNAL_OAUTH_ISSUER = 'https://sts.windows.net/$ENTRA_TENANT/'
  EXTERNAL_OAUTH_JWS_KEYS_URL = 'https://login.microsoftonline.com/$ENTRA_TENANT/discovery/v2.0/keys'
  EXTERNAL_OAUTH_AUDIENCE_LIST = ('api://$app')
  EXTERNAL_OAUTH_TOKEN_USER_MAPPING_CLAIM = 'upn'
  EXTERNAL_OAUTH_SNOWFLAKE_USER_MAPPING_ATTRIBUTE = 'login_name';
CREATE USER IF NOT EXISTS TRESOR_PERSON LOGIN_NAME = '$upn' DEFAULT_ROLE = $role;
GRANT ROLE $role TO USER TRESOR_PERSON;
SQL
	cat >"$dir/entra-issuer.yaml" <<YAML
  - issuer: $login/v2.0
    audience: $ENTRA_API_CLIENT_ID
    client_id: $ENTRA_PEOPLE_CLIENT_ID
    scopes: [openid, offline_access, $ENTRA_API_URI/access_as_user]
    human_flows: [device_code]
    roles_claim: roles
    service: {claim: idtyp, equals: app, client_claim: azp}
    exchange: {client_id: $ENTRA_API_CLIENT_ID, client_auth: key_file, key_file: $dir/obo.pem, x5t: $thumb, assertion_audience: token_endpoint, grant: on_behalf_of}
YAML
	echo "snowflake_live: run design/snowflake/entra.sql in Snowflake; add design/snowflake/entra-issuer.yaml to the service's issuers"
	echo "snowflake_live: the secret's token: mint+exchange://api://<the resource>?scope=api://<the resource>/session:role:$role (in entra-secret.json)"
	python3 -c 'import json,sys; app,cat,role=sys.argv[1:]; print(json.dumps({"type":"iceberg","provider":"config","scope":[cat],
"params":{"uri":cat,"token":"mint+exchange://api://%s?scope=api://%s/session:role:%s" % (app,app,role)},"redact_keys":[]}))' \
		"$app" "https://$SNOWFLAKE_HOST/polaris/api/catalog" "$role" >"$dir/entra-secret.json"
	echo "snowflake_live: up"
}

token_of() { python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))'; }

check() {
	local device code person minted cat
	cat="https://$SNOWFLAKE_HOST/polaris/api/catalog"
	echo "snowflake_live: sign in as a person (device code) - for duckdb-secrets"
	device="$(curl -s -X POST "$login/oauth2/v2.0/devicecode" -d "client_id=$ENTRA_PEOPLE_CLIENT_ID" \
		--data-urlencode "scope=$ENTRA_API_URI/access_as_user")"
	echo "$device" | python3 -c 'import json,sys; print("snowflake_live:", json.load(sys.stdin)["message"])'
	code="$(echo "$device" | python3 -c 'import json,sys; print(json.load(sys.stdin)["device_code"])')"
	person=""
	# tokens and codes go to curl on stdin, never on its command line (ps)
	for _ in $(seq 90); do
		sleep 5
		person="$(printf '%s' "$code" | curl -s -X POST "$login/oauth2/v2.0/token" -d "client_id=$ENTRA_PEOPLE_CLIENT_ID" \
			-d grant_type=urn:ietf:params:oauth:grant-type:device_code --data-urlencode "device_code@-" | token_of)"
		[ -n "$person" ] && break
	done
	unset code device
	[ -n "$person" ] || { echo "snowflake_live: no sign-in within 7 minutes" >&2; exit 1; }

	echo "snowflake_live: the person reads sf_ice_user from the service: their Snowflake token, minted by OBO"
	minted="$(printf 'Authorization: Bearer %s' "$person" | curl -s -H @- "$tresor/v1/secrets/sf_ice_user" | python3 -c '
import json,sys
b = json.load(sys.stdin)
t = b.get("params", {}).get("token", "")
if not t: print("refused: " + str(b.get("detail", "no token, no detail")), file=sys.stderr)
print(t)')"
	unset person
	[ -n "$minted" ] || exit 1
	echo "$minted" | cut -d. -f2 | python3 -c 'import base64,json,sys; s=sys.stdin.read().strip(); s+="="*(-len(s)%4); c=json.loads(base64.urlsafe_b64decode(s))
print("snowflake_live: minted: scp %s, aud is the resource %s, upn %s" % (c.get("scp"), str(c.get("aud","")).startswith("api://"), "upn" in c))'

	echo "snowflake_live: Horizon with the person's token"
	printf 'Authorization: Bearer %s' "$minted" | curl -s -o /dev/null -w 'snowflake_live: namespaces %{http_code}\n' -H @- \
		"$cat/v1/TRESOR_LAB/namespaces"
	printf 'Authorization: Bearer %s' "$minted" | curl -s -H @- -H "X-Iceberg-Access-Delegation: vended-credentials" \
		"$cat/v1/TRESOR_LAB/namespaces/SALES/tables/ORDERS" | python3 -c '
import json,sys
d = json.load(sys.stdin)
if "error" in d: print("snowflake_live: table refused:", d["error"].get("message")); sys.exit(1)
print("snowflake_live: table loaded; vended credentials:", bool(d.get("storage-credentials") or d.get("config",{}).get("s3.access-key-id")))'
	unset minted
}

down() {
	local app key
	echo "snowflake_live: Entra back as it was"
	if [ -f "$dir/obo.crt" ]; then
		key="$(az ad app credential list --id "$ENTRA_API_CLIENT_ID" --cert --query "[?displayName=='CN=$cert_name'].keyId | [0]" -o tsv)"
		[ -n "$key" ] || { echo "snowflake_live: the certificate CN=$cert_name is not on duckdb-secrets - remove it by hand; the local files are kept" >&2; exit 1; }
		az ad app credential delete --id "$ENTRA_API_CLIENT_ID" --key-id "$key" --cert -o none
		rm -f "$dir/obo.key" "$dir/obo.crt" "$dir/obo.pem" "$dir/entra-issuer.yaml" "$dir/entra-secret.json"
	fi
	app="$(resource)"
	if [ -n "$app" ]; then
		az ad app permission delete --id "$ENTRA_API_CLIENT_ID" --api "$app" -o none 2>/dev/null || true
		az ad app delete --id "$app" -o none     # soft-deleted for 30 days; its delegated grant goes with its principal
	fi
	echo "snowflake_live: down (run design/snowflake/teardown.sql in Snowflake)"
}

case "${1:-}" in
up) up ;;
check) check ;;
down) down ;;
*) echo "usage: $0 up|check|down" >&2; exit 2 ;;
esac
