#!/usr/bin/env bash
# The Container Apps recipe, live (spec 002): deploy/azure-container-apps into the live resource group, with
# the Entra tenant's registrations (tresor's website/docs/entra.md), then DuckDB (tresor's build) against it as
# the node app: it logs in, creates a secret, one that stays in Key Vault (ref+azkv://), and finds both through
# DuckDB's lookup - across the replicas behind the ingress. Nothing is printed of a secret, a token or the
# tenant's ids.
#
#   set -a; . ~/projects/hugr-lab/tresor/.env; set +a
#   scripts/dev/aca_live.sh up [postgres|sqlserver]    # deploy (idempotent) and check
#   scripts/dev/aca_live.sh check                      # check what is deployed
#   scripts/dev/aca_live.sh down                       # delete what the recipe made (the vault purged)
#
# ENTRA_TENANT, ENTRA_API_CLIENT_ID, ENTRA_API_URI, ENTRA_PEOPLE_CLIENT_ID, ENTRA_NODE_CLIENT_ID, ENTRA_NODE_SECRET;
# TRESOR (default ~/projects/hugr-lab/tresor, built); TRESOR_LIVE_RG (tresor-server-live), TRESOR_LIVE_LOCATION.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
rg="${TRESOR_LIVE_RG:-tresor-server-live}"
location="${TRESOR_LIVE_LOCATION:-westeurope}"
tresor="${TRESOR:-$HOME/projects/hugr-lab/tresor}"
deployment=tresor-aca
for name in ENTRA_TENANT ENTRA_API_CLIENT_ID ENTRA_API_URI ENTRA_PEOPLE_CLIENT_ID ENTRA_NODE_CLIENT_ID ENTRA_NODE_SECRET; do
	[ -n "${!name:-}" ] || { echo "aca_live: $name is not set (the tresor repository's .env)" >&2; exit 1; }
done
issuer="https://login.microsoftonline.com/$ENTRA_TENANT/v2.0"

up() {
	local database="${1:-sqlserver}"
	echo "aca_live: deploying the recipe ($database) into $rg - several minutes"
	az group create -n "$rg" -l "$location" -o none
	az deployment group create -g "$rg" -n "$deployment" -f "$root/deploy/azure-container-apps/main.bicep" -o none \
		-p database="$database" \
		-p issuers="[{issuer: '$issuer', audience: '$ENTRA_API_CLIENT_ID', client_id: '$ENTRA_PEOPLE_CLIENT_ID', scopes: [openid, offline_access, '$ENTRA_API_URI/access_as_user'], human_flows: [authorization_code, device_code], service_flows: [client_credentials, private_key_jwt], roles_claim: roles, service: {claim: idtyp, equals: app, client_claim: azp}}]" \
		-p admins="[role:secrets_admin, 'client:$ENTRA_NODE_CLIENT_ID']"
}

output() { az deployment group show -g "$rg" -n "$deployment" --query "properties.outputs.$1.value" -o tsv; }

check() {
	local url vault host node_role="${ENTRA_NODE_ROLE:-nodes}"
	url="$(output url)"
	vault="$(output vault)"
	host="${url#https://}"
	echo "aca_live: waiting for $host to be ready"
	for _ in $(seq 60); do
		curl -sf "$url/.well-known/duckdb-secrets" >/dev/null && break
		sleep 10
	done
	curl -sf "$url/.well-known/duckdb-secrets" >/dev/null || { echo "aca_live: the service does not answer" >&2; exit 1; }
	# a secret in the recipe's vault, for a reference: the signed-in user writes it (Secrets Officer)
	me="$(az ad signed-in-user show --query id -o tsv)"
	scope="$(az keyvault show -n "$vault" --query id -o tsv)"
	if [ -z "$(az role assignment list --assignee "$me" --role "Key Vault Secrets Officer" --scope "$scope" --query '[0].id' -o tsv)" ]; then
		az role assignment create --assignee-object-id "$me" --assignee-principal-type User \
			--role "Key Vault Secrets Officer" --scope "$scope" -o none
	fi
	ref_ok=0
	for _ in $(seq 30); do
		if az keyvault secret set --vault-name "$vault" -n duckdb-aca-live --value "aca-live-from-vault" -o none 2>/dev/null; then
			ref_ok=1
			break
		fi
		sleep 10
	done
	[ "$ref_ok" = 1 ] || { echo "aca_live: the reference's secret could not be set" >&2; exit 1; }
	echo "aca_live: DuckDB as the node, through $host"
	local out
	out="$(printf "LOAD '%s';
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:%s', FLOW 'client_credentials', CLIENT_ID '%s', CLIENT_SECRET '%s', ISSUER '%s', OAUTH_SCOPE '%s/.default');
ATTACH 'tresor:%s' AS corp (SECRET node);
SELECT 'live:whoami|' || login FROM corp.whoami();
CREATE OR REPLACE PERSISTENT SECRET aca_inline IN corp (TYPE s3, KEY_ID 'AKIA-ACA-LIVE', SECRET 'inline-live', SCOPE 's3://aca-live-inline');
CREATE OR REPLACE PERSISTENT SECRET aca_ref IN corp (TYPE s3, KEY_ID 'AKIA-ACA-REF', SECRET 'ref+azkv://%s/duckdb-aca-live', SCOPE 's3://aca-live-ref');
SELECT 'live:secrets|' || count(*) FROM corp.secrets() WHERE name IN ('aca_inline', 'aca_ref');
SELECT 'live:granted|' || principal FROM corp.grant_secret('aca_inline', 'role:%s', ['use']);
SELECT 'live:granted|' || principal FROM corp.grant_secret('aca_ref', 'role:%s', ['use']);
SELECT 'live:lookup|' || name FROM which_secret('s3://aca-live-inline/x.parquet', 's3');
SELECT 'live:lookup|' || name FROM which_secret('s3://aca-live-ref/x.parquet', 's3');
" "$tresor/build/release/extension/tresor/tresor.duckdb_extension" "$host" "$ENTRA_NODE_CLIENT_ID" "$ENTRA_NODE_SECRET" \
		"$issuer" "$ENTRA_API_URI" "$host" "$vault" "$node_role" "$node_role" | "$tresor/build/release/duckdb" -unsigned -list -noheader 2>&1 |
		sed -E -e 's/eyJ[A-Za-z0-9._-]*/<token>/g')" || true
	echo "$out" | grep -E '^live:|Error' | sed "s/$ENTRA_NODE_SECRET/<secret>/g"
	echo "$out" | grep -q '^live:secrets|2$' && echo "$out" | grep -q '^live:lookup|aca_ref$' || {
		echo "aca_live: the check did not pass" >&2
		exit 1
	}
	# the reference, read in the vault by the service at each fetch - through the ingress, so across the replicas:
	# fetched by the protocol with the node's own token (DuckDB's lookup picks a secret by its descriptor; its
	# material is fetched only when a file system needs it). Compared here, never printed
	local token ok=0
	token="$(curl -s -X POST "https://login.microsoftonline.com/$ENTRA_TENANT/oauth2/v2.0/token" -d grant_type=client_credentials \
		-d "client_id=$ENTRA_NODE_CLIENT_ID" --data-urlencode "client_secret=$ENTRA_NODE_SECRET" \
		--data-urlencode "scope=$ENTRA_API_URI/.default" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))')"
	for _ in 1 2 3 4; do
		curl -s -H "Authorization: Bearer $token" "$url/v1/secrets/aca_ref" | python3 -c '
import json, sys
b = json.load(sys.stdin)
s = b.get("params", {}).get("secret")
v = s.get("value") if isinstance(s, dict) else s
sys.exit(0 if v == "aca-live-from-vault" and "secret" in b.get("redact_keys", []) else 1)' && ok=$((ok + 1))
	done
	unset token
	[ "$ok" = 4 ] || { echo "aca_live: the reference resolved in $ok of 4 fetches" >&2; exit 1; }
	echo "aca_live: the reference resolved in Key Vault at each of 4 fetches, redacted"
	echo "aca_live: replicas running: $(az containerapp replica list -g "$rg" -n tresor-app --query 'length(@)' -o tsv)"
	echo "aca_live: the service on Container Apps created, granted and served both secrets - one from Key Vault"
}

down() {
	local vault
	vault="$(output vault 2>/dev/null || true)"
	echo "aca_live: deleting what the recipe made in $rg (the live KEK vault of azure_live.sh stays)"
	# the deployment's own resources, the app first, then what it used
	for type in Microsoft.App/containerApps Microsoft.App/managedEnvironments Microsoft.OperationalInsights/workspaces \
		Microsoft.Sql/servers Microsoft.DBforPostgreSQL/flexibleServers Microsoft.ManagedIdentity/userAssignedIdentities \
		Microsoft.KeyVault/vaults; do
		for id in $(az deployment group show -g "$rg" -n "$deployment" --query "properties.outputResources[].id" -o tsv |
			grep -i "/providers/$type/[^/]*$" || true); do
			az resource delete --ids "$id" -o none || true
		done
	done
	# the recipe's vault has purge protection: it stays deleted-but-recoverable for its retention (7 days)
	[ -n "$vault" ] && echo "aca_live: $vault is soft-deleted; purge protection keeps its name for 7 days"
}

case "${1:-}" in
up) up "${2:-sqlserver}" && check ;;
check) check ;;
down) down ;;
*) echo "usage: aca_live.sh up [postgres|sqlserver] | check | down" >&2; exit 1 ;;
esac
