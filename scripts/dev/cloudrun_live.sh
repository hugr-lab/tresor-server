#!/usr/bin/env bash
# The GCP recipe, live (spec 020; the owner's yes on 2026-10-14): deploy/gcp-cloud-run applied in a project of its
# own - Cloud Run, Cloud KMS, Secret Manager, Cloud SQL by Private Service Connect (no public address) - with the
# Entra tenant's registrations as the issuer (tresor's website/docs/entra.md); then the protocol through the URL
# with the node app's token (a secret, a ref+gcp, a variable), and the recipe's jobs. Nothing secret is printed.
#
#   set -a; . ~/projects/hugr-lab/tresor/.env; set +a
#   TRESOR_GCP_BILLING=… scripts/dev/cloudrun_live.sh up      # the project, terraform apply, then check
#   scripts/dev/cloudrun_live.sh check                        # the protocol and the jobs, again
#   scripts/dev/cloudrun_live.sh down                         # terraform destroy, the project deleted
#
# ENTRA_TENANT, ENTRA_API_CLIENT_ID, ENTRA_API_URI, ENTRA_NODE_CLIENT_ID, ENTRA_NODE_SECRET; TERRAFORM (terraform);
# TRESOR_GCP_REGION (europe-west1). The run's state (the project id, terraform's state - which holds the
# database's first password, dead after db-init) is kept in tresor-cloudrun-live under ~/.cache, 0700.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
region="${TRESOR_GCP_REGION:-europe-west1}"
tf="${TERRAFORM:-terraform}"
work="${TRESOR_CLOUDRUN_STATE:-$HOME/.cache}/tresor-cloudrun-live"
mkdir -p "$work" && chmod 700 "$work"
for name in ENTRA_TENANT ENTRA_API_CLIENT_ID ENTRA_API_URI ENTRA_NODE_CLIENT_ID ENTRA_NODE_SECRET; do
	[ -n "${!name:-}" ] || { echo "cloudrun_live: $name is not set (the tresor repository's .env)" >&2; exit 1; }
done
[ -f "$work/project" ] || echo "tresor-run-$(date +%m%d)-$(openssl rand -hex 2)" >"$work/project"
project="$(cat "$work/project")"
issuer="https://login.microsoftonline.com/$ENTRA_TENANT/v2.0"
# the recipe, copied: its state and plugins in the run's directory, never in the repository
mod="$work/module"
rm -rf "$mod" && cp -R "$root/deploy/gcp-cloud-run" "$mod" && rm -rf "$mod/.terraform"
# terraform as the signed-in gcloud user: a short-lived token in the environment, never on a command line
t() {
	(cd "$mod" && GOOGLE_OAUTH_ACCESS_TOKEN="$(gcloud auth print-access-token)" GOOGLE_CLOUD_QUOTA_PROJECT="$project" \
		TF_DATA_DIR="$work/tf" "$tf" "$1" -state="$work/terraform.tfstate" "${@:2}")
}
ours() { [ "$(gcloud projects describe "$project" --format 'value(labels.purpose)' 2>/dev/null)" = tresor-server-live ]; }
vars() {
	cat >"$work/run.tfvars" <<EOT
project             = "$project"
region              = "$region"
issuers             = "[{issuer: '$issuer', audience: '$ENTRA_API_CLIENT_ID', roles_claim: roles, service: {claim: idtyp, equals: app, client_claim: azp}}]"
admins              = "['client:$ENTRA_NODE_CLIENT_ID']"
database_tier       = "db-f1-micro"
deletion_protection = false
EOT
}

up() {
	[ -n "${TRESOR_GCP_BILLING:-}" ] || { echo "cloudrun_live: TRESOR_GCP_BILLING is not set" >&2; exit 1; }
	if gcloud projects describe "$project" >/dev/null 2>&1; then
		ours || { echo "cloudrun_live: project $project exists and is not this script's" >&2; exit 1; }
	else
		gcloud projects create "$project" --name "tresor recipe live" --labels purpose=tresor-server-live
	fi
	gcloud billing projects link "$project" --billing-account "$TRESOR_GCP_BILLING" >/dev/null
	# the provider itself needs these to read the project and enable the rest
	gcloud --project "$project" services enable cloudresourcemanager.googleapis.com serviceusage.googleapis.com --quiet
	vars
	echo "cloudrun_live: terraform apply (the recipe) - Cloud SQL takes a while"
	(cd "$mod" && TF_DATA_DIR="$work/tf" "$tf" init -input=false >/dev/null)
	t apply -input=false -auto-approve -var-file="$work/run.tfvars"
	check
}

token() {
	curl -s -X POST "https://login.microsoftonline.com/$ENTRA_TENANT/oauth2/v2.0/token" -d grant_type=client_credentials \
		-d "client_id=$ENTRA_NODE_CLIENT_ID" --data-urlencode "client_secret=$ENTRA_NODE_SECRET" \
		--data-urlencode "scope=$ENTRA_API_URI/.default" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))'
}

check() {
	local url tok me
	url="$(t output -raw url)"
	echo "cloudrun_live: the service at $url"
	for _ in $(seq 30); do curl -sf "$url/readyz" >/dev/null && break; sleep 10; done
	curl -sf "$url/readyz" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ", d.get("status"), {k: v for k, v in d.get("checks", {}).items()})'
	echo "cloudrun_live: a secret in Secret Manager, for a reference"
	gcloud --project "$project" secrets describe duckdb-run-live >/dev/null 2>&1 ||
		printf '%s' run-live-from-secret-manager | gcloud --project "$project" secrets create duckdb-run-live --data-file=- --quiet >/dev/null
	tok="$(token)"
	[ -n "$tok" ] || { echo "cloudrun_live: no token for the node" >&2; exit 1; }
	me="client:$ENTRA_NODE_CLIENT_ID"
	api() { curl -s -o "$work/out" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$url$2" ${3:+-d "$3"}; }
	local code ok=0
	api DELETE /v1/secrets/run_live >/dev/null
	code="$(api PUT /v1/secrets/run_live "{\"type\":\"http\",\"provider\":\"config\",\"scope\":[\"https://run-live.example\"],\"params\":{\"bearer_token\":\"ref+gcp://$project/duckdb-run-live\",\"extra\":\"inline-value\"},\"redact_keys\":[\"bearer_token\"]}")"
	echo "  secret written: $code"; [ "$code" = 200 ] || [ "$code" = 201 ] || ok=1
	code="$(api PUT /v1/secrets/run_live/grants/me "{\"principal\":\"$me\",\"verbs\":[\"use\"]}")"
	echo "  granted: $code"; [ "$code" = 200 ] || [ "$code" = 201 ] || ok=1
	code="$(api GET /v1/secrets/run_live)"
	if [ "$code" = 200 ] && python3 -c 'import json,sys; p=json.load(open(sys.argv[1]))["params"]; sys.exit(0 if p.get("bearer_token")=="run-live-from-secret-manager" and p.get("extra")=="inline-value" else 1)' "$work/out"; then
		echo "  read: the reference resolved in Secret Manager, the inline value as written"
	else
		echo "  read: $code - not as written" >&2; ok=1
	fi
	api DELETE /v1/variables/run_live >/dev/null
	code="$(api PUT /v1/variables/run_live '{"value":"run-live-variable"}')"
	echo "  variable written: $code"; [ "$code" = 200 ] || [ "$code" = 201 ] || ok=1
	api DELETE /v1/secrets/run_live >/dev/null
	api DELETE /v1/variables/run_live >/dev/null
	rm -f "$work/out"
	unset tok
	echo "cloudrun_live: the recipe's jobs"
	for job in mac reseal-rotate rewrap; do
		if gcloud --project "$project" run jobs execute "tresor-$job" --region "$region" --wait --quiet >/dev/null 2>&1; then
			echo "  $job: succeeded"
		else
			echo "  $job: FAILED" >&2; ok=1
		fi
	done
	if gcloud --project "$project" logging read 'resource.type="cloud_run_revision"' --limit 500 --format 'value(textPayload)' 2>/dev/null | grep -qF run-live-from-secret-manager; then
		echo "cloudrun_live: a value reached the log" >&2; ok=1
	fi
	[ "$ok" = 0 ] && echo "cloudrun_live: passed" || { echo "cloudrun_live: failed" >&2; exit 1; }
}

down() {
	ours || { echo "cloudrun_live: project $project is not this script's: not deleted" >&2; exit 1; }
	vars
	if [ -f "$work/terraform.tfstate" ]; then
		(cd "$mod" && TF_DATA_DIR="$work/tf" "$tf" init -input=false >/dev/null)
		t destroy -input=false -auto-approve -var-file="$work/run.tfvars" || echo "cloudrun_live: destroy did not finish - the project goes anyway" >&2
	fi
	gcloud projects delete "$project" --quiet
	rm -rf "$work"
	echo "cloudrun_live: deleted"
}

case "${1:-}" in
up | check | down) "$1" ;;
*) echo "usage: cloudrun_live.sh up | check | down" >&2; exit 2 ;;
esac
