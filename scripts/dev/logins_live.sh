#!/usr/bin/env bash
# tresor's service logins, live (tresor spec 027; asked by tresor's session, the owner's yes on 2026-10-14): the
# Container Apps recipe (aca_live.sh) as the duckdb-secrets/1 service, and DuckDB (tresor's image) logging in to it
#   1. as a user-assigned managed identity, directly (FLOW 'managed_identity') - a Container Apps job;
#   2. as acl-node, the identity its federated credential (FLOW 'federated', ASSERTION_SOURCE
#      'azure_managed_identity') - a Container Apps job;
#   3. as acl-node from an AKS pod, its projected ServiceAccount token the assertion (FLOW 'federated',
#      ASSERTION_FILE) - workload identity.
# Nothing is printed of a token, a secret or the tenant's ids. Everything the run adds to the tenant is removed by
# down, and checked gone through Graph.
#
#   set -a; . ~/projects/hugr-lab/tresor/.env; set +a
#   scripts/dev/logins_live.sh up         # the service, the identity, the tenant's grants, AKS (no image needed)
#   TRESOR_DUCKDB_IMAGE=ghcr.io/...@sha256:... scripts/dev/logins_live.sh check
#                                         # the three logins: tresor's /live/check.sh mi|fed|aks (or
#                                         # TRESOR_LOGIN_CMD_MI, _FED, _AKS)
#   scripts/dev/logins_live.sh down       # the group deleted, the tenant as it was
#
# ENTRA_TENANT, ENTRA_API_CLIENT_ID, ENTRA_API_URI, ENTRA_PEOPLE_CLIENT_ID, ENTRA_NODE_CLIENT_ID, ENTRA_NODE_SECRET
# (aca_live.sh's); TRESOR_LOGINS_RG (tresor-server-logins), TRESOR_LOGINS_LOCATION (northeurope),
# TRESOR_LOGINS_VM (Standard_D2s_v6), TRESOR_ACL_NODE (the app registration's display name, acl-node).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
rg="${TRESOR_LOGINS_RG:-tresor-server-logins}"
location="${TRESOR_LOGINS_LOCATION:-northeurope}"
vm="${TRESOR_LOGINS_VM:-Standard_D2s_v6}"
acl_name="${TRESOR_ACL_NODE:-acl-node}"
mi=tresor-logins-mi
cluster=tresor-logins
ns=tresor-logins
sa=duckdb
fic_mi=tresor-logins-mi
fic_aks=tresor-logins-aks
role="${TRESOR_LOGINS_ROLE:-nodes}"
work="${TRESOR_LOGINS_STATE:-$HOME/.cache}/tresor-logins-live"
for name in ENTRA_TENANT ENTRA_API_CLIENT_ID ENTRA_API_URI; do
	[ -n "${!name:-}" ] || { echo "logins_live: $name is not set (the tresor repository's .env)" >&2; exit 1; }
done
issuer="https://login.microsoftonline.com/$ENTRA_TENANT/v2.0"
mkdir -p "$work" && chmod 700 "$work"
export KUBECONFIG="$work/kubeconfig"

graph() { az rest --method "$1" --url "https://graph.microsoft.com/v1.0/$2" "${@:3}"; }
acl_app() { az ad app list --display-name "$acl_name" --query '[0].appId' -o tsv; }
api_sp() { az ad sp show --id "$ENTRA_API_CLIENT_ID" --query id -o tsv; }
mi_field() { az identity show -g "$rg" -n "$mi" --query "$1" -o tsv; }
service_url() { az deployment group show -g "$rg" -n tresor-aca --query properties.outputs.url.value -o tsv; }

# federated <name> <issuer> <subject>: a federated credential on acl-node (made once)
federated() {
	local app; app="$(acl_app)"
	[ -n "$app" ] || { echo "logins_live: no app registration named $acl_name" >&2; exit 1; }
	if [ -z "$(az ad app federated-credential list --id "$app" --query "[?name=='$1'].name | [0]" -o tsv)" ]; then
		az ad app federated-credential create --id "$app" -o none --parameters "{\"name\":\"$1\",\"issuer\":\"$2\",
			\"subject\":\"$3\",\"audiences\":[\"api://AzureADTokenExchange\"],\"description\":\"tresor's login checks (scripts/dev/logins_live.sh)\"}"
	fi
}

# jobs: the Container Apps jobs (manual) with tresor's image - DuckDB as the identity, and as acl-node by it
jobs() {
	local env url principal
	env="$(az containerapp env list -g "$rg" --query '[0].name' -o tsv)"
	url="$(service_url)"
	for job in mi fed; do
		local cmd_var; cmd_var="TRESOR_LOGIN_CMD_$(tr a-z A-Z <<<"$job")"
		az containerapp job delete -g "$rg" -n "tresor-login-$job" --yes -o none 2>/dev/null || true
		az containerapp job create -g "$rg" -n "tresor-login-$job" --environment "$env" -o none \
			--trigger-type Manual --replica-timeout 600 --replica-retry-limit 0 --parallelism 1 --replica-completion-count 1 \
			--image "$TRESOR_DUCKDB_IMAGE" --cpu 0.5 --memory 1Gi --mi-user-assigned "$(mi_field id)" \
			--env-vars "TRESOR_URL=$url" "TRESOR_ISSUER=$issuer" "TRESOR_AUDIENCE=$ENTRA_API_CLIENT_ID" \
			"TRESOR_API_URI=$ENTRA_API_URI" "TRESOR_MI_CLIENT_ID=$(mi_field clientId)" "TRESOR_ACL_CLIENT_ID=$(acl_app)" \
			--command "${TRESOR_LOGIN_SHELL:-/bin/sh}" --args "-c" "${!cmd_var:-/live/check.sh $job}"
	done
}

up() {
	echo "logins_live: the service (the Container Apps recipe, postgres) in $rg, $location"
	TRESOR_LIVE_RG="$rg" TRESOR_LIVE_LOCATION="$location" "$root/scripts/dev/aca_live.sh" up postgres

	echo "logins_live: a user-assigned identity, app role $role on duckdb-secrets (before any token is cached)"
	az identity create -g "$rg" -n "$mi" -l "$location" -o none
	local principal sp role_id
	principal="$(mi_field principalId)"
	sp="$(api_sp)"
	role_id="$(az ad sp show --id "$ENTRA_API_CLIENT_ID" --query "appRoles[?value=='$role'].id | [0]" -o tsv)"
	[ -n "$role_id" ] || { echo "logins_live: duckdb-secrets has no app role $role" >&2; exit 1; }
	for _ in $(seq 12); do # a new identity's principal reaches Graph after a while
		[ "$(graph get "servicePrincipals/$sp/appRoleAssignedTo" --query "length(value[?principalId=='$principal'])" -o tsv)" -gt 0 ] && break
		graph post "servicePrincipals/$sp/appRoleAssignedTo" --headers Content-Type=application/json -o none \
			--body "{\"principalId\":\"$principal\",\"resourceId\":\"$sp\",\"appRoleId\":\"$role_id\"}" 2>/dev/null || true
		sleep 10
	done

	echo "logins_live: acl-node trusts the identity (a federated credential)"
	federated "$fic_mi" "$issuer" "$principal"

	echo "logins_live: AKS (1 node, $vm, OIDC issuer, workload identity) - several minutes"
	az aks create -g "$rg" -n "$cluster" -l "$location" --tier free --node-count 1 -s "$vm" \
		--enable-oidc-issuer --enable-workload-identity --generate-ssh-keys -o none
	az aks get-credentials -g "$rg" -n "$cluster" --file "$KUBECONFIG" --overwrite-existing -o none
	local oidc
	oidc="$(az aks show -g "$rg" -n "$cluster" --query oidcIssuerProfile.issuerUrl -o tsv)"
	echo "logins_live: acl-node trusts the cluster's ServiceAccount $ns/$sa"
	federated "$fic_aks" "$oidc" "system:serviceaccount:$ns:$sa"
	kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n "$ns" create serviceaccount "$sa" --dry-run=client -o yaml | kubectl apply -f -
	echo "logins_live: up - the service at $url"
}

# job <name> <command>: a Container Apps job's run, its exit
runjob() {
	local name="tresor-login-$1" exec status
	exec="$(az containerapp job start -g "$rg" -n "$name" --query name -o tsv)"
	for _ in $(seq 60); do
		status="$(az containerapp job execution show -g "$rg" -n "$name" --job-execution-name "$exec" --query properties.status -o tsv)"
		[ "$status" = Succeeded ] || [ "$status" = Failed ] && break
		sleep 10
	done
	echo "logins_live: $1: $status"
	[ "$status" = Succeeded ]
}

check() {
	local ok=0 url
	[ -n "${TRESOR_DUCKDB_IMAGE:-}" ] || { echo "logins_live: TRESOR_DUCKDB_IMAGE (tresor's DuckDB image) is not set" >&2; exit 1; }
	url="$(service_url)"
	jobs
	runjob mi || ok=1
	runjob fed || ok=1
	echo "logins_live: aks: DuckDB in a pod, its projected token the assertion"
	kubectl -n "$ns" delete pod duckdb --ignore-not-found --wait
	kubectl apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata: {name: duckdb, namespace: $ns}
spec:
  serviceAccountName: $sa
  automountServiceAccountToken: false
  restartPolicy: Never
  securityContext: {runAsNonRoot: true, runAsUser: 65532, fsGroup: 65532}
  containers:
    - name: duckdb
      image: $TRESOR_DUCKDB_IMAGE
      command: ["${TRESOR_LOGIN_SHELL:-/bin/sh}", "-c", "${TRESOR_LOGIN_CMD_AKS:-/live/check.sh aks}"]
      env:
        - {name: TRESOR_URL, value: "$url"}
        - {name: TRESOR_ISSUER, value: "$issuer"}
        - {name: TRESOR_AUDIENCE, value: "$ENTRA_API_CLIENT_ID"}
        - {name: TRESOR_API_URI, value: "$ENTRA_API_URI"}
        - {name: TRESOR_ACL_CLIENT_ID, value: "$(acl_app)"}
        - {name: TRESOR_ASSERTION_FILE, value: /var/run/secrets/tresor/token}
      volumeMounts: [{name: token, mountPath: /var/run/secrets/tresor, readOnly: true}]
  volumes:
    - name: token
      projected:
        defaultMode: 0440   # tresor refuses a token file others may read
        sources: [{serviceAccountToken: {path: token, audience: api://AzureADTokenExchange, expirationSeconds: 3600}}]
YAML
	kubectl -n "$ns" wait --for=jsonpath='{.status.phase}'=Succeeded pod/duckdb --timeout 300s || ok=1
	kubectl -n "$ns" logs duckdb --tail 40 || true
	[ "$ok" = 0 ] && echo "logins_live: every login passed" || { echo "logins_live: a login failed" >&2; exit 1; }
}

down() {
	local app sp principal id
	echo "logins_live: the tenant as it was"
	app="$(acl_app)"
	if [ -n "$app" ]; then
		for f in "$fic_mi" "$fic_aks"; do
			az ad app federated-credential delete --id "$app" --federated-credential-id "$f" -o none 2>/dev/null || true
		done
	fi
	sp="$(api_sp)"
	principal="$(mi_field principalId 2>/dev/null || true)"
	if [ -n "$principal" ]; then
		for id in $(graph get "servicePrincipals/$sp/appRoleAssignedTo" --query "value[?principalId=='$principal'].id" -o tsv); do
			graph delete "servicePrincipals/$sp/appRoleAssignedTo/$id" -o none
		done
	fi
	echo "logins_live: the group $rg deleted (the recipe's vault stays soft-deleted: purge protection)"
	az group delete -n "$rg" --yes -o none || true
	rm -rf "$work"
	# checked gone
	if [ -n "$app" ] && [ -n "$(az ad app federated-credential list --id "$app" --query "[?starts_with(name, 'tresor-logins')].name" -o tsv)" ]; then
		echo "logins_live: a federated credential is still on $acl_name" >&2; exit 1
	fi
	echo "logins_live: down"
}

case "${1:-}" in
up) up ;;
check) check ;;
down) down ;;
*) echo "usage: logins_live.sh up | check | down" >&2; exit 1 ;;
esac
