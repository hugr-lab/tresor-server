#!/usr/bin/env bash
# The chart on AKS, live (spec 003, e): the Kubernetes store, its KEK in Key Vault reached by workload identity
# (no secret of the service's own), ref+azkv in a secret and a variable, the admission policy. Checked through
# the protocol by scripts/ci/kindcheck, against an OIDC issuer in the cluster (scripts/ci/incluster.sh). Nothing
# secret is printed.
#
#   scripts/dev/aks_live.sh up       # the group, AKS, the vault, the identity, the chart (idempotent where it can)
#   scripts/dev/aks_live.sh check    # through the protocol, again
#   scripts/dev/aks_live.sh down     # delete the group, the custom role; purge the vault
#
# TRESOR_AKS_RG (tresor-server-aks), TRESOR_AKS_LOCATION (westeurope), TRESOR_AKS_VM (Standard_D2s_v6: a family
# with quota), TRESOR_AKS_IMAGE (ghcr.io/hugr-lab/
# tresor-server:edge). The run's state (a kubeconfig, the CA, the issuer's key) is kept in the directory
# tresor-aks-live under TRESOR_AKS_STATE (~/.cache) between up and check; down removes that directory only.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
rg="${TRESOR_AKS_RG:-tresor-server-aks}"
location="${TRESOR_AKS_LOCATION:-westeurope}"
image="${TRESOR_AKS_IMAGE:-ghcr.io/hugr-lab/tresor-server:edge}"
work="${TRESOR_AKS_STATE:-$HOME/.cache}/tresor-aks-live"
cluster=tresor-aks
identity=tresor-aks-id
ns=tresor
sa=tresor
issuer=https://idp.idp.svc/realms/t
role_name="tresor KEK user (aks live, $rg)"
mkdir -p "$work"
chmod 700 "$work"
export KUBECONFIG="$work/kubeconfig"
pids=()
trap 'for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null || true; done' EXIT
. "$root/scripts/ci/incluster.sh"

case "${1:-}" in
up | check | down) ;;
*)
	echo "usage: aks_live.sh up | check | down" >&2
	exit 2
	;;
esac
sha256() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; }
sub="$(az account show --query id -o tsv)"
vault="tresoraks$(printf '%s' "$sub$rg" | sha256 | cut -c1-12)"

build_kindcheck() {
	(cd "$root" && GOWORK=off CGO_ENABLED=0 go build -o "$work/kindcheck" ./scripts/ci/kindcheck)
}

# retry <tries> <command...>: RBAC takes a while to reach the data plane
retry() {
	local n="$1"
	shift
	for _ in $(seq "$n"); do
		"$@" 2>/dev/null && return 0
		sleep 10
	done
	"$@"
}

# assign <object id> <principal type> <role> <scope>: once, retried while the principal propagates
assign() {
	if [ -z "$(az role assignment list --assignee "$1" --role "$3" --scope "$4" --query '[0].id' -o tsv 2>/dev/null)" ]; then
		retry 30 az role assignment create --assignee-object-id "$1" --assignee-principal-type "$2" --role "$3" --scope "$4" -o none
	fi
}

up() {
	build_kindcheck
	echo "aks_live: the group and the cluster (workload identity, OIDC issuer) - several minutes"
	az group create -n "$rg" -l "$location" --tags purpose=tresor-server-live-aks -o none
	if ! az aks show -g "$rg" -n "$cluster" -o none 2>/dev/null; then
		az aks create -g "$rg" -n "$cluster" --tier free --node-count 1 --node-vm-size "${TRESOR_AKS_VM:-Standard_D2s_v6}" \
			--enable-oidc-issuer --enable-workload-identity --generate-ssh-keys -o none
	fi
	az aks get-credentials -g "$rg" -n "$cluster" --file "$KUBECONFIG" --overwrite-existing -o none

	echo "aks_live: the vault, its KEK (RSA, wrap/unwrap/sign) and a secret for a reference"
	if az keyvault show-deleted -n "$vault" -o none 2>/dev/null; then
		echo "aks_live: vault $vault is soft-deleted from a run before: az keyvault purge -n $vault, or recover it" >&2
		exit 1
	fi
	if ! az keyvault show -n "$vault" -o none 2>/dev/null; then
		az keyvault create -g "$rg" -n "$vault" -l "$location" --enable-rbac-authorization true --retention-days 7 -o none
	fi
	local vault_id me
	vault_id="$(az keyvault show -n "$vault" --query id -o tsv)"
	me="$(az ad signed-in-user show --query id -o tsv)"
	for role in "Key Vault Crypto Officer" "Key Vault Secrets Officer"; do
		assign "$me" User "$role" "$vault_id"
	done
	if ! az keyvault key show --vault-name "$vault" -n tresor-kek -o none 2>/dev/null; then
		retry 30 az keyvault key create --vault-name "$vault" -n tresor-kek --kty RSA --size 3072 \
			--ops wrapKey unwrapKey sign -o none
	fi
	retry 30 az keyvault secret set --vault-name "$vault" -n duckdb-aks-live --value aks-live-from-the-vault -o none

	echo "aks_live: the service's identity: the custom role on the key, Secrets User on the secret, federated"
	az identity create -g "$rg" -n "$identity" -o none
	local client principal key_id oidc role_id
	client="$(az identity show -g "$rg" -n "$identity" --query clientId -o tsv)"
	principal="$(az identity show -g "$rg" -n "$identity" --query principalId -o tsv)"
	key_id="$vault_id/keys/tresor-kek"
	role_id="$(az role definition list --custom-role-only true --name "$role_name" --query '[0].name' -o tsv)"
	if [ -z "$role_id" ]; then
		az role definition create -o none --role-definition "{
			\"Name\": \"$role_name\", \"Description\": \"tresor-server's KEK: get, wrap, unwrap, sign (the root)\",
			\"Actions\": [], \"DataActions\": [\"Microsoft.KeyVault/vaults/keys/read\",
			\"Microsoft.KeyVault/vaults/keys/wrap/action\", \"Microsoft.KeyVault/vaults/keys/unwrap/action\",
			\"Microsoft.KeyVault/vaults/keys/sign/action\"],
			\"AssignableScopes\": [\"/subscriptions/$sub/resourceGroups/$rg\"]}"
	fi
	assign "$principal" ServicePrincipal "$role_name" "$key_id"
	assign "$principal" ServicePrincipal "Key Vault Secrets User" "$vault_id/secrets/duckdb-aks-live"
	oidc="$(az aks show -g "$rg" -n "$cluster" --query oidcIssuerProfile.issuerUrl -o tsv)"
	az identity federated-credential show -g "$rg" --identity-name "$identity" -n tresor-sa -o none 2>/dev/null ||
		az identity federated-credential create -g "$rg" --identity-name "$identity" -n tresor-sa -o none \
		--issuer "$oidc" --subject "system:serviceaccount:$ns:$sa" --audiences api://AzureADTokenExchange

	echo "aks_live: in the cluster, a CA and an OIDC issuer for the check"
	# the issuer is made with this state's CA and key: either missing, both are made again
	if [ ! -f "$work/ca.crt" ] || [ ! -f "$work/idp/key.pem" ]; then
		ca_make
		kubectl delete namespace idp --ignore-not-found --wait >/dev/null
		issuer_up "$issuer"
	fi
	kubectl get namespace "$ns" -o name >/dev/null 2>&1 || kubectl create namespace "$ns"
	kubectl -n "$ns" create configmap ca --from-file=ca.crt="$work/ca.crt" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

	echo "aks_live: the chart - the Kubernetes store, the KEK by workload identity"
	cat >"$work/values.yaml" <<EOF
image: {repository: ${image%:*}, tag: ${image##*:}, pullPolicy: Always}
serviceAccount: {name: $sa}
workloadIdentity: {enabled: true, clientId: $client}
# the run's CA beside the system's (Key Vault's TLS): SSL_CERT_DIR adds, SSL_CERT_FILE would replace
env: [{name: SSL_CERT_DIR, value: /etc/tresor-ca}]
extraVolumes: [{name: ca, configMap: {name: ca}}]
extraVolumeMounts: [{name: ca, mountPath: /etc/tresor-ca, readOnly: true}]
config:
  public_url: https://tresor.example.com
  state: {kind: kubernetes}
  keys: {kind: azurekeyvault, key: https://$vault.vault.azure.net/keys/tresor-kek}
  azure: {identity: workload}
  material: {azkv: {allow: [{vault: $vault, prefixes: [duckdb-]}]}}
  issuers:
    - {issuer: $issuer, audience: duckdb-secrets, roles_claim: roles}
  policy: {admins: [role:secrets_admin]}
EOF
	helm upgrade --install tresor "$root/deploy/helm/tresor-server" -n "$ns" -f "$work/values.yaml" --wait --timeout 300s ||
		{ kubectl -n "$ns" get pods; kubectl -n "$ns" logs -l app.kubernetes.io/instance=tresor --tail 40; exit 1; }
	check
}

check() {
	[ -x "$work/kindcheck" ] || build_kindcheck
	forward "$ns" tresor-tresor-server
	echo "aks_live: readiness"
	curl -sf "http://127.0.0.1:$port/readyz" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ", d.get("status"), {k: v for k, v in d.get("checks", {}).items()})'
	"$work/kindcheck" smoke "$work/idp" "$issuer" "http://127.0.0.1:$port" "ref+azkv://$vault/duckdb-aks-live" aks-live-from-the-vault
	echo "aks_live: the resources, sealed"
	kubectl -n "$ns" get tresor
	if kubectl -n "$ns" delete tresorkeyring active --dry-run=server 2>"$work/denied"; then
		echo "aks_live: a hand delete was admitted" >&2
		exit 1
	fi
	grep -q "only tresor-server writes its resources" "$work/denied" || { cat "$work/denied" >&2; exit 1; }
	echo "aks_live: the admission policy refuses a hand delete"
	local logs
	logs="$(kubectl -n "$ns" logs -l app.kubernetes.io/instance=tresor --tail 500)"
	if grep -qF aks-live-from-the-vault <<<"$logs"; then
		echo "aks_live: a value reached the log" >&2
		exit 1
	fi
	echo "aks_live: passed"
}

down() {
	echo "aks_live: deleting $rg (the cluster, the identity, the assignments), the custom role; purging the vault"
	if [ "$(az group exists -n "$rg")" = true ]; then
		az group delete -n "$rg" --yes -o none # waits: the vault is soft-deleted once it returns
	fi
	if [ -n "$(az role definition list --custom-role-only true --name "$role_name" --query '[0].name' -o tsv)" ]; then
		az role definition delete --name "$role_name" -o none
	fi
	if az keyvault show-deleted -n "$vault" -o none 2>/dev/null; then
		az keyvault purge -n "$vault" -o none
	fi
	rm -rf "$work"
	echo "aks_live: deleted (AKS may have made NetworkWatcherRG in $location: Azure's, free, shared - left alone)"
}

"$1"
