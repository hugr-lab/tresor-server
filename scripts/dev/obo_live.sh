#!/usr/bin/env bash
# Entra On-Behalf-Of, live (spec 013; spec 006's managed identity as a federated credential): the Container Apps
# recipe (aca_live.sh, deployed with TRESOR_LIVE_OBO=1) mints a token_exchange secret by OBO for a person, the
# service authenticated at Entra by its managed identity - the app registration's federated credential, no
# secret anywhere. Nothing is printed of a token, a secret or the tenant's ids.
#
#   set -a; . ~/projects/hugr-lab/tresor/.env; set +a
#   TRESOR_LIVE_OBO=1 scripts/dev/aca_live.sh up postgres     # the service, its issuer with exchange.grant on_behalf_of
#   scripts/dev/obo_live.sh up        # Entra: a downstream API, its delegated permission consented, the federated credential
#   scripts/dev/obo_live.sh check     # a person signs in (device code), reads the secret: a token minted by OBO
#   scripts/dev/obo_live.sh down      # Entra back as it was (then aca_live.sh down)
#
# ENTRA_TENANT, ENTRA_API_CLIENT_ID, ENTRA_API_URI, ENTRA_PEOPLE_CLIENT_ID, ENTRA_NODE_CLIENT_ID, ENTRA_NODE_SECRET;
# TRESOR_LIVE_RG (tresor-server-live).
set -euo pipefail
rg="${TRESOR_LIVE_RG:-tresor-server-live}"
deployment=tresor-aca
downstream_name=tresor-obo-downstream
fic_name=tresor-managed-identity
for name in ENTRA_TENANT ENTRA_API_CLIENT_ID ENTRA_API_URI ENTRA_PEOPLE_CLIENT_ID ENTRA_NODE_CLIENT_ID ENTRA_NODE_SECRET; do
	[ -n "${!name:-}" ] || { echo "obo_live: $name is not set (the tresor repository's .env)" >&2; exit 1; }
done
login="https://login.microsoftonline.com/$ENTRA_TENANT"

output() { az deployment group show -g "$rg" -n "$deployment" --query "properties.outputs.$1.value" -o tsv; }
downstream() { az ad app list --display-name "$downstream_name" --query '[0].appId' -o tsv; }

up() {
	local identity principal app scope_id api_object
	identity="$(az deployment group show -g "$rg" -n "$deployment" --query "properties.outputResources[].id" -o tsv |
		grep -i '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/[^/]*$' | head -1)"
	[ -n "$identity" ] || { echo "obo_live: no managed identity in $rg - run TRESOR_LIVE_OBO=1 aca_live.sh up first" >&2; exit 1; }
	principal="$(az identity show --ids "$identity" --query principalId -o tsv)"

	echo "obo_live: the downstream API ($downstream_name), with one delegated scope"
	app="$(downstream)"
	if [ -z "$app" ]; then
		app="$(az ad app create --display-name "$downstream_name" --sign-in-audience AzureADMyOrg --query appId -o tsv)"
		az ad sp create --id "$app" -o none
	fi
	scope_id="$(az ad app show --id "$app" --query "api.oauth2PermissionScopes[?value=='access'].id | [0]" -o tsv)"
	if [ -z "$scope_id" ]; then
		scope_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
		az ad app update --id "$app" --identifier-uris "api://$app" -o none
		az ad app update --id "$app" --set "api={\"requestedAccessTokenVersion\":2,\"oauth2PermissionScopes\":[{\"id\":\"$scope_id\",\"value\":\"access\",\"type\":\"User\",\"isEnabled\":true,\"adminConsentDisplayName\":\"Access the OBO test API\",\"adminConsentDescription\":\"tresor-server's OBO live check\",\"userConsentDisplayName\":\"Access the OBO test API\",\"userConsentDescription\":\"tresor-server's OBO live check\"}]}" -o none
	fi

	echo "obo_live: duckdb-secrets may call it on behalf of users (admin consent)"
	az ad app permission add --id "$ENTRA_API_CLIENT_ID" --api "$app" --api-permissions "$scope_id=Scope" -o none 2>/dev/null || true
	# admin-consent may answer before the permission has propagated, and grant nothing: the delegated grant is
	# checked, and made through Graph when missing
	local sp_api sp_down
	sp_api="$(az ad sp show --id "$ENTRA_API_CLIENT_ID" --query id -o tsv)"
	sp_down="$(az ad sp show --id "$app" --query id -o tsv)"
	for _ in $(seq 12); do
		az ad app permission admin-consent --id "$ENTRA_API_CLIENT_ID" -o none 2>/dev/null || true
		[ "$(az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/$sp_api/oauth2PermissionGrants" \
			--query "length(value[?resourceId=='$sp_down'])" -o tsv)" -gt 0 ] && break
		az rest --method post --url https://graph.microsoft.com/v1.0/oauth2PermissionGrants --headers Content-Type=application/json \
			--body "{\"clientId\":\"$sp_api\",\"consentType\":\"AllPrincipals\",\"resourceId\":\"$sp_down\",\"scope\":\"access\"}" \
			-o none 2>/dev/null || true
		sleep 10
	done

	echo "obo_live: the federated credential - duckdb-secrets trusts the service's managed identity"
	if [ -z "$(az ad app federated-credential list --id "$ENTRA_API_CLIENT_ID" --query "[?name=='$fic_name'].name | [0]" -o tsv)" ]; then
		az ad app federated-credential create --id "$ENTRA_API_CLIENT_ID" -o none --parameters "{\"name\":\"$fic_name\",
			\"issuer\":\"$login/v2.0\",\"subject\":\"$principal\",\"audiences\":[\"api://AzureADTokenExchange\"],
			\"description\":\"tresor-server's managed identity (scripts/dev/obo_live.sh)\"}"
	fi
	echo "obo_live: up"
}

# token_of reads access_token from a token endpoint's answer on stdin
token_of() { python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))'; }

check() {
	local url app device person admin roles role ok
	url="$(output url)"
	app="$(downstream)"
	[ -n "$app" ] || { echo "obo_live: no downstream API - run obo_live.sh up" >&2; exit 1; }

	echo "obo_live: sign in as a person (device code) - for the service's API"
	device="$(curl -s -X POST "$login/oauth2/v2.0/devicecode" -d "client_id=$ENTRA_PEOPLE_CLIENT_ID" \
		--data-urlencode "scope=$ENTRA_API_URI/access_as_user")"
	echo "$device" | python3 -c 'import json,sys; print("obo_live:", json.load(sys.stdin)["message"])'
	code="$(echo "$device" | python3 -c 'import json,sys; print(json.load(sys.stdin)["device_code"])')"
	person=""
	for _ in $(seq 90); do
		sleep 5
		person="$(curl -s -X POST "$login/oauth2/v2.0/token" -d "client_id=$ENTRA_PEOPLE_CLIENT_ID" \
			-d grant_type=urn:ietf:params:oauth:grant-type:device_code --data-urlencode "device_code=$code" | token_of)"
		[ -n "$person" ] && break
	done
	unset code device
	[ -n "$person" ] || { echo "obo_live: no sign-in within 7 minutes" >&2; exit 1; }
	roles="$(echo "$person" | cut -d. -f2 | python3 -c 'import base64,json,sys; s=sys.stdin.read().strip(); s+="="*(-len(s)%4); print(" ".join(json.loads(base64.urlsafe_b64decode(s)).get("roles",[])))')"
	role="${roles%% *}"
	[ -n "$role" ] || { echo "obo_live: the person's token carries no app role of duckdb-secrets - assign one" >&2; exit 1; }

	echo "obo_live: the node (an administrator) writes a token_exchange secret for the downstream API, granted to role:$role"
	admin="$(curl -s -X POST "$login/oauth2/v2.0/token" -d grant_type=client_credentials -d "client_id=$ENTRA_NODE_CLIENT_ID" \
		--data-urlencode "client_secret=$ENTRA_NODE_SECRET" --data-urlencode "scope=$ENTRA_API_URI/.default" | token_of)"
	curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $admin" "$url/v1/secrets/obo_live"
	curl -sf -o /dev/null -X PUT -H "Authorization: Bearer $admin" -H 'Content-Type: application/json' "$url/v1/secrets/obo_live" \
		-d "{\"type\":\"http\",\"provider\":\"token_exchange\",\"scope\":[\"https://obo-live.example\"],\"params\":{\"audience\":\"$app\"},\"redact_keys\":[]}" ||
		{ echo "obo_live: the secret was not written" >&2; exit 1; }
	curl -sf -o /dev/null -X PUT -H "Authorization: Bearer $admin" -H 'Content-Type: application/json' \
		"$url/v1/secrets/obo_live/grants/obo" -d "{\"principal\":\"role:$role\",\"verbs\":[\"use\"]}" ||
		{ echo "obo_live: the grant was not written" >&2; exit 1; }

	echo "obo_live: the person reads it: a token minted by OBO"
	ok="$(curl -s -H "Authorization: Bearer $person" "$url/v1/secrets/obo_live" | APP="$app" PERSON="$person" python3 -c '
import base64, json, os, sys
b = json.load(sys.stdin)
t = b.get("params", {}).get("bearer_token", "")
if not t:
    print("refused: " + str(b.get("detail", b)))
    sys.exit(0)
def claims(tok):
    s = tok.split(".")[1]; s += "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))
m, p = claims(t), claims(os.environ["PERSON"])
good = m.get("aud") == os.environ["APP"] and m.get("oid") == p.get("oid") and t != os.environ["PERSON"]
print("ok" if good else "wrong token: aud %s, for the person %s" % (m.get("aud") == os.environ["APP"], m.get("oid") == p.get("oid")))')"
	unset person admin
	echo "obo_live: $ok"
	[ "$ok" = ok ] || exit 1
	echo "obo_live: a token minted by Entra's On-Behalf-Of for the person, for the downstream API - the service holds no secret"
}

down() {
	local app
	echo "obo_live: Entra back as it was"
	az ad app federated-credential delete --id "$ENTRA_API_CLIENT_ID" --federated-credential-id "$fic_name" -o none 2>/dev/null || true
	app="$(downstream)"
	if [ -n "$app" ]; then
		az ad app permission delete --id "$ENTRA_API_CLIENT_ID" --api "$app" -o none 2>/dev/null || true
		az ad app delete --id "$app" -o none
	fi
	echo "obo_live: down"
}

case "${1:-}" in
up) up ;;
check) check ;;
down) down ;;
*) echo "usage: obo_live.sh up | check | down" >&2; exit 1 ;;
esac
