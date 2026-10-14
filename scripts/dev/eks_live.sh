#!/usr/bin/env bash
# AWS, live (spec 012, c; the owner's yes on 2026-10-14): the chart on EKS, its identity by IRSA (no key of the
# service's own) - the Kubernetes store, the KEK in KMS (an encrypt key and an HMAC key), a reference in Secrets
# Manager; then the chart's maintenance jobs (spec 019). Checked through the protocol by scripts/ci/kindcheck against
# an OIDC issuer in the cluster (scripts/ci/incluster.sh). RDS by IAM is the ECS recipe's run (ecs_live.sh). Nothing
# secret is printed.
#
#   AWS_PROFILE=tresor-live scripts/dev/eks_live.sh up | check | down
#
# TRESOR_EKS_IMAGE (ghcr.io/hugr-lab/tresor-server:v0.3.3), TRESOR_EKS_NODE (t3.medium). The run's state (a
# kubeconfig, the CA, the issuer's key, the keys' ids) in tresor-eks-live under ~/.cache.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
region="${AWS_REGION:-eu-central-1}"
image="${TRESOR_EKS_IMAGE:-ghcr.io/hugr-lab/tresor-server:v0.3.3}"
work="${TRESOR_EKS_STATE:-$HOME/.cache}/tresor-eks-live"
cluster=tresor-live
ns=tresor
sa=tresor
role=tresor-live-eks
issuer=https://idp.idp.svc/realms/t
mkdir -p "$work" && chmod 700 "$work"
export KUBECONFIG="$work/kubeconfig" AWS_REGION="$region"
pids=()
trap 'for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null || true; done' EXIT
. "$root/scripts/ci/incluster.sh"
account="$(aws sts get-caller-identity --query Account --output text)"

build_kindcheck() { (cd "$root" && GOWORK=off CGO_ENABLED=0 go build -o "$work/kindcheck" ./scripts/ci/kindcheck); }

# key <alias> <usage> <spec>: a KMS key by its alias, made once; its ARN
key() {
	local arn
	arn="$(aws kms describe-key --key-id "alias/$1" --query KeyMetadata.Arn --output text 2>/dev/null || true)"
	if [ -z "$arn" ] || [ "$arn" = None ]; then
		arn="$(aws kms create-key --description "tresor-server live (eks_live)" --key-usage "$2" --key-spec "$3" \
			--tags TagKey=purpose,TagValue=tresor-server-live --query KeyMetadata.Arn --output text)"
		aws kms create-alias --alias-name "alias/$1" --target-key-id "$arn"
	fi
	echo "$arn"
}

up() {
	build_kindcheck
	echo "eks_live: the cluster (eksctl: a VPC, 2 nodes, the OIDC provider for IRSA) - about 20 minutes"
	if ! eksctl get cluster --name "$cluster" --region "$region" >/dev/null 2>&1; then
		eksctl create cluster --name "$cluster" --region "$region" --nodes 2 --node-type "${TRESOR_EKS_NODE:-t3.medium}" \
			--with-oidc --managed --tags purpose=tresor-server-live --kubeconfig "$KUBECONFIG"
	fi
	eksctl utils write-kubeconfig --cluster "$cluster" --region "$region" --kubeconfig "$KUBECONFIG" >/dev/null

	echo "eks_live: KMS - an encrypt key and an HMAC key; a secret in Secrets Manager"
	local kek mac
	kek="$(key tresor-live-eks-kek ENCRYPT_DECRYPT SYMMETRIC_DEFAULT)"
	mac="$(key tresor-live-eks-root GENERATE_VERIFY_MAC HMAC_256)"
	aws secretsmanager describe-secret --secret-id duckdb/eks-live >/dev/null 2>&1 ||
		aws secretsmanager create-secret --name duckdb/eks-live --secret-string eks-live-from-secrets-manager >/dev/null

	echo "eks_live: IRSA - a role for $ns/$sa: the two keys, the secrets under duckdb/"
	cat >"$work/policy.json" <<JSON
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Action": ["kms:Encrypt", "kms:Decrypt"], "Resource": "$kek"},
  {"Effect": "Allow", "Action": ["kms:GenerateMac"], "Resource": "$mac"},
  {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": "arn:aws:secretsmanager:$region:$account:secret:duckdb/*"}]}
JSON
	local policy="arn:aws:iam::$account:policy/$role"
	aws iam get-policy --policy-arn "$policy" >/dev/null 2>&1 ||
		aws iam create-policy --policy-name "$role" --policy-document "file://$work/policy.json" >/dev/null
	eksctl create iamserviceaccount --cluster "$cluster" --region "$region" --namespace "$ns" --name "$sa" \
		--role-name "$role" --role-only --attach-policy-arn "$policy" --approve >/dev/null

	echo "eks_live: in the cluster, a CA and an OIDC issuer for the check"
	if [ ! -f "$work/ca.crt" ] || [ ! -f "$work/idp/key.pem" ]; then
		ca_make
		kubectl delete namespace idp --ignore-not-found --wait >/dev/null
		issuer_up "$issuer"
	fi
	kubectl get namespace "$ns" -o name >/dev/null 2>&1 || kubectl create namespace "$ns"
	kubectl -n "$ns" create configmap ca --from-file=ca.crt="$work/ca.crt" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

	echo "eks_live: the chart - the Kubernetes store, the KEK in KMS, ref+aws, by IRSA"
	cat >"$work/values.yaml" <<YAML
image: {repository: ${image%:*}, tag: ${image##*:}, pullPolicy: Always}
replicas: 2
serviceAccount:
  name: $sa
  annotations: {eks.amazonaws.com/role-arn: arn:aws:iam::$account:role/$role}
env: [{name: SSL_CERT_DIR, value: /etc/tresor-ca}]
extraVolumes: [{name: ca, configMap: {name: ca}}]
extraVolumeMounts: [{name: ca, mountPath: /etc/tresor-ca, readOnly: true}]
config:
  public_url: https://tresor.example.com
  state: {kind: kubernetes}
  aws: {region: $region}
  keys: {kind: awskms, key: $kek, mac_key: $mac}
  material: {aws: {allow: [{prefixes: [duckdb/]}]}}
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
	[[ "$state" == *Complete* ]] || { echo "eks_live: job $1: $state" >&2; exit 1; }
	echo "eks_live: job $1: complete"
}

check() {
	[ -x "$work/kindcheck" ] || build_kindcheck
	forward "$ns" tresor-tresor-server
	echo "eks_live: readiness"
	curl -sf "http://127.0.0.1:$port/readyz" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ", d.get("status"), {k: v for k, v in d.get("checks", {}).items()})'
	"$work/kindcheck" smoke "$work/idp" "$issuer" "http://127.0.0.1:$port" "ref+aws://duckdb/eks-live" eks-live-from-secrets-manager
	echo "eks_live: the chart's jobs (spec 019) - as the service, by IRSA"
	runjob reseal-rotate
	runjob rewrap
	"$work/kindcheck" smoke "$work/idp" "$issuer" "http://127.0.0.1:$port" "ref+aws://duckdb/eks-live" eks-live-from-secrets-manager
	echo "eks_live: the data keys under KMS"
	kubectl -n "$ns" get tresordatakeys -o jsonpath='{range .items[*]}{.spec.kekID}{"\n"}{end}' | sed 's/[0-9]\{12\}/<acct>/; s/^/  /'
	local logs
	logs="$(kubectl -n "$ns" logs -l app.kubernetes.io/instance=tresor --tail 500)"
	if grep -qF eks-live-from-secrets-manager <<<"$logs"; then echo "eks_live: a value reached the log" >&2; exit 1; fi
	echo "eks_live: passed"
}

down() {
	echo "eks_live: the cluster (eksctl: its VPC, nodes, the IRSA role's stack)"
	eksctl delete cluster --name "$cluster" --region "$region" --wait || true
	local policy="arn:aws:iam::$account:policy/$role"
	aws iam delete-policy --policy-arn "$policy" 2>/dev/null || true
	for a in tresor-live-eks-kek tresor-live-eks-root; do
		local id
		id="$(aws kms describe-key --key-id "alias/$a" --query KeyMetadata.KeyId --output text 2>/dev/null || true)"
		if [ -n "$id" ] && [ "$id" != None ]; then
			aws kms delete-alias --alias-name "alias/$a"
			aws kms schedule-key-deletion --key-id "$id" --pending-window-in-days 7 >/dev/null
		fi
	done
	aws secretsmanager delete-secret --secret-id duckdb/eks-live --force-delete-without-recovery >/dev/null 2>&1 || true
	rm -rf "$work"
	echo "eks_live: deleted (the KMS keys scheduled for deletion in 7 days)"
}

case "${1:-}" in
up | check | down) "$1" ;;
*) echo "usage: eks_live.sh up | check | down" >&2; exit 2 ;;
esac
