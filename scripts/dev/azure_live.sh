#!/usr/bin/env bash
# The Key Vault KEK, live (spec 002): a resource group of its own, a Key Vault on the RBAC permission model,
# an RSA key, and the signed-in az user allowed to use it; then the live test seals, opens, rotates the key in
# the vault and rewraps. Nothing is printed of a key or a token.
#
#   scripts/dev/azure_live.sh up        # create (idempotent) and run the live test
#   scripts/dev/azure_live.sh test      # run the live test against what exists
#   scripts/dev/azure_live.sh down      # delete the resource group, and purge the vault
#
# Environment: AZURE_SUBSCRIPTION (default: the az CLI's), TRESOR_LIVE_RG (tresor-server-live),
# TRESOR_LIVE_LOCATION (westeurope), TRESOR_LIVE_VAULT (tresor-live-<8 hex of the subscription>).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
rg="${TRESOR_LIVE_RG:-tresor-server-live}"
location="${TRESOR_LIVE_LOCATION:-westeurope}"
if [ -n "${AZURE_SUBSCRIPTION:-}" ]; then az account set --subscription "$AZURE_SUBSCRIPTION"; fi
sub="$(az account show --query id -o tsv)"
vault="${TRESOR_LIVE_VAULT:-tresor-live-${sub:0:8}}"
key=tresor-kek
kek="https://$vault.vault.azure.net/keys/$key"

up() {
	echo "azure_live: resource group $rg in $location"
	az group create -n "$rg" -l "$location" -o none
	if ! az keyvault show -n "$vault" -g "$rg" -o none 2>/dev/null; then
		if az keyvault show-deleted -n "$vault" -o none 2>/dev/null; then
			echo "azure_live: key vault $vault was deleted, not purged: recovering it"
			az keyvault recover -n "$vault" -o none
		else
			echo "azure_live: key vault $vault (RBAC)"
			az keyvault create -n "$vault" -g "$rg" -l "$location" --enable-rbac-authorization true -o none
		fi
	fi
	me="$(az ad signed-in-user show --query id -o tsv)"
	scope="$(az keyvault show -n "$vault" -g "$rg" --query id -o tsv)"
	# the developer creates and rotates the key (Crypto Officer); the service's own role would be
	# Key Vault Crypto Service Encryption User, on the key only
	if [ -z "$(az role assignment list --assignee "$me" --role "Key Vault Crypto Officer" --scope "$scope" \
		--query '[0].id' -o tsv)" ]; then
		az role assignment create --assignee-object-id "$me" --assignee-principal-type User \
			--role "Key Vault Crypto Officer" --scope "$scope" -o none || {
			echo "azure_live: the role could not be assigned - Owner or User Access Administrator is needed on $rg" >&2
			exit 1
		}
	fi
	ready=0
	for _ in $(seq 30); do
		if az keyvault key list --vault-name "$vault" -o none 2>/dev/null; then
			ready=1
			break
		fi
		sleep 10 # the role assignment takes a while to reach the vault
	done
	[ "$ready" = 1 ] || {
		echo "azure_live: the vault still refuses the signed-in user after 5 minutes" >&2
		exit 1
	}
	if ! az keyvault key show --vault-name "$vault" -n "$key" -o none 2>/dev/null; then
		echo "azure_live: RSA key $key"
		az keyvault key create --vault-name "$vault" -n "$key" --kty RSA --size 3072 --ops wrapKey unwrapKey -o none
	fi
}

live() {
	echo "azure_live: sealing through $kek"
	(cd "$root" && GOWORK=off TRESOR_LIVE_KEK="$kek" TRESOR_LIVE_ROTATE=1 \
		go test -tags live -count=1 -run TestLive -v ./internal/keys/azurekeyvault)
}

down() {
	echo "azure_live: deleting $rg"
	az group delete -n "$rg" --yes -o none
	az keyvault purge -n "$vault" -l "$location" -o none 2>/dev/null || true
}

case "${1:-}" in
up) up && live ;;
test) live ;;
down) down ;;
*)
	echo "usage: azure_live.sh up | test | down" >&2
	exit 1
	;;
esac
