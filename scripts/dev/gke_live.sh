#!/usr/bin/env bash
# GCP, live (spec 012, c; the owner's yes on 2026-10-14): the chart on GKE Autopilot, its identity by Workload
# Identity (no key of the service's own) - the KEK in Cloud KMS (an encrypt key and a MAC key), a reference in
# Secret Manager, PostgreSQL in Cloud SQL by IAM database authentication (TLS verify-full to the instance's DNS
# name); then the chart's maintenance jobs (spec 019): mac, reseal -rotate -retire, rewrap. Checked through the
# protocol by scripts/ci/kindcheck against an OIDC issuer in the cluster (scripts/ci/incluster.sh). Nothing secret
# is printed.
#
# A project of its own, deleted whole by down. For the run only, the Cloud SQL instance's public IP takes any
# address (0.0.0.0/0) - logins are IAM tokens over TLS, no password user is left; in production: a private IP or
# Private Service Connect (docs: GCP).
#
#   scripts/dev/gke_live.sh up       # the project, the cluster, KMS, the secret, Cloud SQL, the chart; then check
#   scripts/dev/gke_live.sh check    # through the protocol, and the jobs, again
#   scripts/dev/gke_live.sh down     # the project deleted (30 days pending, not billed)
#
# TRESOR_GCP_BILLING (the billing account), TRESOR_GCP_PROJECT (tresor-live-<mmdd>-<random>, kept in the state),
# TRESOR_GCP_REGION (europe-west1), TRESOR_GKE_IMAGE (ghcr.io/hugr-lab/tresor-server:v0.3.1). The run's state (the
# project id, a kubeconfig, the CA, the issuer's key) is kept in tresor-gke-live under TRESOR_GKE_STATE (~/.cache).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
region="${TRESOR_GCP_REGION:-europe-west1}"
image="${TRESOR_GKE_IMAGE:-ghcr.io/hugr-lab/tresor-server:v0.3.1}"
work="${TRESOR_GKE_STATE:-$HOME/.cache}/tresor-gke-live"
cluster=tresor-gke
ns=tresor
sa=tresor
gsa=tresor
sql=tresor-pg
issuer=https://idp.idp.svc/realms/t
mkdir -p "$work" && chmod 700 "$work"
export KUBECONFIG="$work/kubeconfig"
# kubectl logs in to GKE with gcloud's plugin (gcloud components install gke-gcloud-auth-plugin)
PATH="$PATH:$(dirname "$(readlink -f "$(command -v gcloud)")")"
pids=()
trap 'for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null || true; done' EXIT
. "$root/scripts/ci/incluster.sh"

case "${1:-}" in
up | check | down) ;;
*) echo "usage: gke_live.sh up | check | down" >&2; exit 2 ;;
esac
if [ ! -f "$work/project" ]; then
	echo "${TRESOR_GCP_PROJECT:-tresor-live-$(date +%m%d)-$(openssl rand -hex 2)}" >"$work/project"
fi
project="$(cat "$work/project")"
email="$gsa@$project.iam.gserviceaccount.com"
ring="projects/$project/locations/$region/keyRings/tresor"
g() { gcloud --project "$project" --quiet "$@"; }

build_kindcheck() { (cd "$root" && GOWORK=off CGO_ENABLED=0 go build -o "$work/kindcheck" ./scripts/ci/kindcheck); }

# retry <tries> <command...>: IAM takes a while to reach the services
retry() {
	local n="$1"; shift
	for _ in $(seq "$n"); do "$@" 2>/dev/null && return 0; sleep 10; done
	"$@"
}

up() {
	[ -n "${TRESOR_GCP_BILLING:-}" ] || { echo "gke_live: TRESOR_GCP_BILLING (the billing account) is not set" >&2; exit 1; }
	build_kindcheck
	echo "gke_live: the project $project, its billing, the APIs"
	gcloud projects describe "$project" >/dev/null 2>&1 || gcloud projects create "$project" --name "tresor live" --labels purpose=tresor-server-live
	gcloud billing projects link "$project" --billing-account "$TRESOR_GCP_BILLING" >/dev/null
	g services enable container.googleapis.com cloudkms.googleapis.com secretmanager.googleapis.com \
		sqladmin.googleapis.com iam.googleapis.com compute.googleapis.com dns.googleapis.com

	echo "gke_live: Cloud SQL (PostgreSQL, IAM authentication, a Google-managed CA: a DNS name) - in the background"
	if ! g sql instances describe "$sql" >/dev/null 2>&1; then
		g sql instances create "$sql" --database-version POSTGRES_16 --edition ENTERPRISE --tier db-f1-micro \
			--region "$region" --server-ca-mode GOOGLE_MANAGED_CAS_CA --ssl-mode ENCRYPTED_ONLY \
			--database-flags cloudsql.iam_authentication=on --authorized-networks 0.0.0.0/0 \
			--root-password "$(openssl rand -hex 24)" --async >/dev/null
	fi

	echo "gke_live: GKE Autopilot (Workload Identity) - several minutes"
	g container clusters describe "$cluster" --region "$region" >/dev/null 2>&1 ||
		g container clusters create-auto "$cluster" --region "$region" >/dev/null
	g container clusters get-credentials "$cluster" --region "$region" >/dev/null

	echo "gke_live: the service's account; Cloud KMS: an encrypt key and a MAC key; a secret"
	g iam service-accounts describe "$email" >/dev/null 2>&1 || g iam service-accounts create "$gsa" --display-name tresor-server
	g kms keyrings describe tresor --location "$region" >/dev/null 2>&1 || g kms keyrings create tresor --location "$region"
	g kms keys describe kek --keyring tresor --location "$region" >/dev/null 2>&1 ||
		g kms keys create kek --keyring tresor --location "$region" --purpose encryption
	g kms keys describe root --keyring tresor --location "$region" >/dev/null 2>&1 ||
		g kms keys create root --keyring tresor --location "$region" --purpose mac --default-algorithm hmac-sha256
	for role in roles/cloudkms.cryptoKeyEncrypterDecrypter roles/cloudkms.viewer; do
		retry 12 g kms keys add-iam-policy-binding kek --keyring tresor --location "$region" --member "serviceAccount:$email" --role "$role" >/dev/null
	done
	retry 12 g kms keys add-iam-policy-binding root --keyring tresor --location "$region" --member "serviceAccount:$email" --role roles/cloudkms.signer >/dev/null
	g secrets describe duckdb-gke-live >/dev/null 2>&1 || printf '%s' gke-live-from-secret-manager | g secrets create duckdb-gke-live --data-file=- >/dev/null
	retry 12 g secrets add-iam-policy-binding duckdb-gke-live --member "serviceAccount:$email" --role roles/secretmanager.secretAccessor >/dev/null
	retry 12 g iam service-accounts add-iam-policy-binding "$email" --role roles/iam.workloadIdentityUser \
		--member "serviceAccount:$project.svc.id.goog[$ns/$sa]" >/dev/null

	echo "gke_live: Cloud SQL ready; the database, the IAM user, its ownership"
	until [ "$(g sql instances describe "$sql" --format 'value(state)')" = RUNNABLE ]; do sleep 20; done
	retry 12 g projects add-iam-policy-binding "$project" --member "serviceAccount:$email" --role roles/cloudsql.instanceUser --condition None >/dev/null
	g sql users list --instance "$sql" --format 'value(name)' | grep -qx "$gsa@$project.iam" ||
		g sql users create "$gsa@$project.iam" --instance "$sql" --type cloud_iam_service_account >/dev/null
	g sql databases list --instance "$sql" --format 'value(name)' | grep -qx tresor || g sql databases create tresor --instance "$sql" >/dev/null
	local pw ip dns
	pw="$(openssl rand -hex 24)" # postgres's, once: the ownership; then replaced and never kept
	g sql users set-password postgres --instance "$sql" --password "$pw" >/dev/null
	ip="$(g sql instances describe "$sql" --format 'value(ipAddresses[0].ipAddress)')"
	dns="$(g sql instances describe "$sql" --format 'value(dnsName)')"
	dns="${dns%.}"
	g sql instances describe "$sql" --format 'value(serverCaCert.cert)' >"$work/server-ca.pem"
	g sql ssl server-ca-certs list --instance "$sql" --format 'value(cert)' >>"$work/server-ca.pem" 2>/dev/null || true
	PGPASSWORD="$pw" docker run --rm -e PGPASSWORD postgres:16-alpine psql "host=$ip user=postgres dbname=tresor sslmode=require" -q \
		-c "GRANT \"$gsa@$project.iam\" TO postgres; ALTER DATABASE tresor OWNER TO \"$gsa@$project.iam\";"
	g sql users set-password postgres --instance "$sql" --password "$(openssl rand -hex 24)" >/dev/null
	unset pw
	[ -n "$dns" ] || { echo "gke_live: the instance has no DNS name (a Google-managed CA gives one)" >&2; exit 1; }
	# the instance's DNS name resolves in the VPC only through a private zone of one's own (Cloud SQL makes none for
	# a public IP): the pods connect by the name its certificate carries - verify-full
	if ! g dns managed-zones describe cloudsql >/dev/null 2>&1; then
		g dns managed-zones create cloudsql --dns-name "$dns." --visibility private --networks default \
			--description "Cloud SQL's DNS name, for verify-full (gke_live)" >/dev/null
	fi
	g dns record-sets describe "$dns." --zone cloudsql --type A >/dev/null 2>&1 ||
		g dns record-sets create "$dns." --zone cloudsql --type A --ttl 300 --rrdatas "$ip" >/dev/null
	echo "gke_live: the instance's DNS name in a private zone of the VPC"

	echo "gke_live: in the cluster, a CA and an OIDC issuer for the check"
	if [ ! -f "$work/ca.crt" ] || [ ! -f "$work/idp/key.pem" ]; then
		ca_make
		kubectl delete namespace idp --ignore-not-found --wait >/dev/null
		issuer_up "$issuer"
	fi
	kubectl get namespace "$ns" -o name >/dev/null 2>&1 || kubectl create namespace "$ns"
	kubectl -n "$ns" create configmap ca --from-file=ca.crt="$work/ca.crt" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
	kubectl -n "$ns" create configmap cloudsql --from-file=server-ca.pem="$work/server-ca.pem" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

	echo "gke_live: the chart - PostgreSQL in Cloud SQL, the KEK in Cloud KMS, ref+gcp, by Workload Identity"
	cat >"$work/values.yaml" <<YAML
image: {repository: ${image%:*}, tag: ${image##*:}, pullPolicy: Always}
replicas: 2
serviceAccount:
  name: $sa
  annotations: {iam.gke.io/gcp-service-account: $email}
env: [{name: SSL_CERT_DIR, value: /etc/tresor-ca}]
extraVolumes: [{name: ca, configMap: {name: ca}}, {name: cloudsql, configMap: {name: cloudsql}}]
extraVolumeMounts: [{name: ca, mountPath: /etc/tresor-ca, readOnly: true}, {name: cloudsql, mountPath: /etc/cloudsql, readOnly: true}]
config:
  public_url: https://tresor.example.com
  state:
    kind: postgres
    dsn: host=$dns user=$gsa@$project.iam dbname=tresor sslmode=verify-full sslrootcert=/etc/cloudsql/server-ca.pem
    auth: gcp
  keys:
    kind: gcpkms
    key: $ring/cryptoKeys/kek
    mac_key: $ring/cryptoKeys/root/cryptoKeyVersions/1
  material: {gcp: {allow: [{project: $project, prefixes: [duckdb-]}]}}
  issuers:
    - {issuer: $issuer, audience: duckdb-secrets, roles_claim: roles}
  policy: {admins: [role:secrets_admin]}
YAML
	helm upgrade --install tresor "$root/deploy/helm/tresor-server" -n "$ns" -f "$work/values.yaml" --wait --timeout 600s ||
		{ kubectl -n "$ns" get pods; kubectl -n "$ns" logs -l app.kubernetes.io/instance=tresor --tail 40; exit 1; }
	check
}

# runjob <command>: a chart's maintenance job (spec 019), to its end
runjob() {
	local job="$1-$(date +%s)" state=""
	kubectl -n "$ns" create job --from="cronjob/tresor-tresor-server-$1" "$job" >/dev/null
	for _ in $(seq 120); do
		state="$(kubectl -n "$ns" get "job/$job" -o jsonpath='{.status.conditions[?(@.status=="True")].type}')"
		[[ "$state" == *Complete* || "$state" == *Failed* ]] && break
		sleep 5
	done
	kubectl -n "$ns" logs "job/$job" --tail 10 | sed 's/^/    /'
	[[ "$state" == *Complete* ]] || { echo "gke_live: job $1: $state" >&2; exit 1; }
	echo "gke_live: job $1: complete"
}

check() {
	[ -x "$work/kindcheck" ] || build_kindcheck
	forward "$ns" tresor-tresor-server
	echo "gke_live: readiness"
	curl -sf "http://127.0.0.1:$port/readyz" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ", d.get("status"), {k: v for k, v in d.get("checks", {}).items()})'
	"$work/kindcheck" smoke "$work/idp" "$issuer" "http://127.0.0.1:$port" "ref+gcp://$project/duckdb-gke-live" gke-live-from-secret-manager
	echo "gke_live: the chart's jobs (spec 019) - as the service, by Workload Identity"
	runjob mac
	runjob reseal-rotate
	runjob rewrap
	"$work/kindcheck" smoke "$work/idp" "$issuer" "http://127.0.0.1:$port" "ref+gcp://$project/duckdb-gke-live" gke-live-from-secret-manager
	local logs
	logs="$(kubectl -n "$ns" logs -l app.kubernetes.io/instance=tresor --tail 500)"
	if grep -qF gke-live-from-secret-manager <<<"$logs"; then echo "gke_live: a value reached the log" >&2; exit 1; fi
	echo "gke_live: passed"
}

down() {
	echo "gke_live: deleting the project $project (everything in it; 30 days pending, not billed)"
	gcloud projects delete "$project" --quiet || true
	rm -rf "$work"
	echo "gke_live: deleted"
}

"$1"
