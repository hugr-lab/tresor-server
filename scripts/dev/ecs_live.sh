#!/usr/bin/env bash
# The AWS recipe, live (spec 021; the owner's yes on 2026-10-14): deploy/aws-ecs applied in the account - ECS Fargate
# behind an HTTPS load balancer at tresor.<zone>, the KEK in KMS, RDS PostgreSQL by IAM in private subnets - with the
# Entra tenant's registrations as the issuer; then the protocol through the URL with the node app's token (a secret
# with a ref+aws, a variable), and the commands by run-task. Nothing secret is printed.
#
#   set -a; . ~/projects/hugr-lab/tresor/.env; set +a
#   AWS_PROFILE=tresor-live TRESOR_AWS_ZONE_ID=… scripts/dev/ecs_live.sh up | check | down
#
# TRESOR_AWS_ZONE (aws.hugr-lab.com), TERRAFORM (terraform). The run's state in tresor-ecs-live under ~/.cache, 0700.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
region="${AWS_REGION:-eu-central-1}"
zone="${TRESOR_AWS_ZONE:-aws.hugr-lab.com}"
domain="tresor.$zone"
tf="${TERRAFORM:-terraform}"
work="${TRESOR_ECS_STATE:-$HOME/.cache}/tresor-ecs-live"
mkdir -p "$work" && chmod 700 "$work"
for name in ENTRA_TENANT ENTRA_API_CLIENT_ID ENTRA_API_URI ENTRA_NODE_CLIENT_ID ENTRA_NODE_SECRET TRESOR_AWS_ZONE_ID; do
	[ -n "${!name:-}" ] || { echo "ecs_live: $name is not set" >&2; exit 1; }
done
issuer="https://login.microsoftonline.com/$ENTRA_TENANT/v2.0"
mod="$work/module"
rm -rf "$mod" && cp -R "$root/deploy/aws-ecs" "$mod" && rm -rf "$mod/.terraform"
t() { (cd "$mod" && TF_DATA_DIR="$work/tf" "$tf" "$1" -state="$work/terraform.tfstate" "${@:2}"); }
vars() {
	cat >"$work/run.tfvars" <<EOT
region              = "$region"
prefix              = "tresor-live"
domain              = "$domain"
route53_zone_id     = "${TRESOR_AWS_ZONE_ID#/hostedzone/}"
issuers             = "[{issuer: '$issuer', audience: '$ENTRA_API_CLIENT_ID', roles_claim: roles, service: {claim: idtyp, equals: app, client_claim: azp}}]"
admins              = "['client:$ENTRA_NODE_CLIENT_ID']"
material_prefixes   = ["duckdb/"]
desired_count       = 2
deletion_protection = false
EOT
}

up() {
	vars
	(cd "$mod" && TF_DATA_DIR="$work/tf" "$tf" init -input=false >/dev/null)
	echo "ecs_live: terraform apply (the recipe) - RDS and the certificate take a while"
	t apply -input=false -auto-approve -var-file="$work/run.tfvars"
	check
}

token() {
	curl -s -X POST "https://login.microsoftonline.com/$ENTRA_TENANT/oauth2/v2.0/token" -d grant_type=client_credentials \
		-d "client_id=$ENTRA_NODE_CLIENT_ID" --data-urlencode "client_secret=$ENTRA_NODE_SECRET" \
		--data-urlencode "scope=$ENTRA_API_URI/.default" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))'
}

check() {
	local url tok code ok=0
	url="https://$domain"
	echo "ecs_live: the service at $url"
	for _ in $(seq 30); do curl -sf "$url/readyz" >/dev/null && break; sleep 10; done
	curl -sf "$url/readyz" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ", d.get("status"), {k: v for k, v in d.get("checks", {}).items()})'
	echo "ecs_live: a secret in Secrets Manager, for a reference"
	aws secretsmanager describe-secret --region "$region" --secret-id duckdb/ecs-live >/dev/null 2>&1 ||
		aws secretsmanager create-secret --region "$region" --name duckdb/ecs-live --secret-string ecs-live-from-secrets-manager >/dev/null
	tok="$(token)"
	[ -n "$tok" ] || { echo "ecs_live: no token for the node" >&2; exit 1; }
	api() { curl -s -o "$work/out" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' "$url$2" ${3:+-d "$3"}; }
	api DELETE /v1/secrets/ecs_live >/dev/null
	code="$(api PUT /v1/secrets/ecs_live '{"type":"http","provider":"config","scope":["https://ecs-live.example"],"params":{"bearer_token":"ref+aws://duckdb/ecs-live","extra":"inline-value"},"redact_keys":["bearer_token"]}')"
	echo "  secret written: $code"; [ "$code" = 200 ] || [ "$code" = 201 ] || ok=1
	code="$(api PUT /v1/secrets/ecs_live/grants/me "{\"principal\":\"role:${ENTRA_NODE_ROLE:-nodes}\",\"verbs\":[\"use\"]}")"
	echo "  granted: $code"; [ "$code" = 200 ] || ok=1
	code="$(api GET /v1/secrets/ecs_live)"
	if [ "$code" = 200 ] && python3 -c 'import json,sys; p=json.load(open(sys.argv[1]))["params"]; sys.exit(0 if p.get("bearer_token")=="ecs-live-from-secrets-manager" and p.get("extra")=="inline-value" else 1)' "$work/out"; then
		echo "  read: the reference resolved in Secrets Manager, the inline value as written"
	else
		echo "  read: $code - not as written" >&2; ok=1
	fi
	api DELETE /v1/variables/ecs_live >/dev/null
	code="$(api PUT /v1/variables/ecs_live '{"value":"ecs-live-variable"}')"
	echo "  variable written: $code"; [ "$code" = 200 ] || [ "$code" = 201 ] || ok=1
	api DELETE /v1/secrets/ecs_live >/dev/null
	api DELETE /v1/variables/ecs_live >/dev/null
	rm -f "$work/out"; unset tok
	echo "ecs_live: the commands by run-task"
	local cluster subnets sg
	cluster="$(t output -raw cluster)"
	subnets="$(t output -json private_subnet_ids | python3 -c 'import json,sys; print(",".join(json.load(sys.stdin)))')"
	sg="$(t output -raw task_security_group)"
	for cmd in '["mac"]' '["reseal","-rotate","-retire"]' '["rewrap"]'; do
		task="$(aws ecs run-task --region "$region" --cluster "$cluster" --launch-type FARGATE --task-definition tresor-live-command \
			--network-configuration "awsvpcConfiguration={subnets=[$subnets],securityGroups=[$sg],assignPublicIp=DISABLED}" \
			--overrides "{\"containerOverrides\":[{\"name\":\"tresor\",\"command\":$cmd}]}" --query 'tasks[0].taskArn' --output text)"
		aws ecs wait tasks-stopped --region "$region" --cluster "$cluster" --tasks "$task"
		code="$(aws ecs describe-tasks --region "$region" --cluster "$cluster" --tasks "$task" --query "tasks[0].containers[?name=='tresor'].exitCode | [0]" --output text)"
		echo "  $cmd: exit $code"; [ "$code" = 0 ] || ok=1
	done
	if aws logs filter-log-events --region "$region" --log-group-name /ecs/tresor-live --filter-pattern '"ecs-live-from-secrets-manager"' --query 'length(events)' --output text 2>/dev/null | grep -qv '^0$'; then
		echo "ecs_live: a value reached the log" >&2; ok=1
	fi
	[ "$ok" = 0 ] && echo "ecs_live: passed" || { echo "ecs_live: failed" >&2; exit 1; }
}

down() {
	vars
	aws secretsmanager delete-secret --region "$region" --secret-id duckdb/ecs-live --force-delete-without-recovery >/dev/null 2>&1 || true
	if [ -f "$work/terraform.tfstate" ]; then
		(cd "$mod" && TF_DATA_DIR="$work/tf" "$tf" init -input=false >/dev/null)
		t destroy -input=false -auto-approve -var-file="$work/run.tfvars"
	fi
	rm -rf "$work"
	echo "ecs_live: destroyed"
}

case "${1:-}" in
up | check | down) "$1" ;;
*) echo "usage: ecs_live.sh up | check | down" >&2; exit 2 ;;
esac
