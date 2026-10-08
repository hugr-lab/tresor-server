#!/usr/bin/env bash
# The chart on a real cluster (spec 003): kind, the image built here, an OIDC issuer and a PostgreSQL behind a
# CA of this run's. Five installs:
#   - the Kubernetes store, the admission policy refusing a hand write and letting the garbage collector
#     delete;
#   - PostgreSQL in the cluster, its password from a Kubernetes Secret (state.password_ref: ref+k8s).
#   - OpenBao in the cluster: Kubernetes auth with a projected token, the KEK in Transit, ref+vault, the
#     Kubernetes store; a second OpenBao as a named source (ref+bao2).
#   - Keycloak 26.6 in the cluster: the service's exchange client authenticated by its projected ServiceAccount
#     token (federated client authentication), a token minted by exchange.
# Each is checked through the protocol (scripts/ci/kindcheck). Needs docker, kind, kubectl, helm, go, openssl.
#
#   scripts/ci/kind.sh            # TRESOR_KIND_KEEP=1 keeps the cluster afterwards
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cluster="${TRESOR_KIND_CLUSTER:-tresor-ci}"
work="$(mktemp -d)"
pids=()
created=""
cleanup() {
	for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null || true; done
	# only a cluster this run made
	if [ -n "$created" ] && [ -z "${TRESOR_KIND_KEEP:-}" ]; then kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
	rm -rf "$work"
}
trap cleanup EXIT
chart="$root/deploy/helm/tresor-server"
issuer=https://idp.idp.svc/realms/t
KUBECTL_CONTEXT="kind-$cluster"
kubectl() { command kubectl --context "$KUBECTL_CONTEXT" "$@"; }
. "$root/scripts/ci/incluster.sh"
helm() { command helm --kube-context "kind-$cluster" "$@"; }
(cd "$root" && GOWORK=off CGO_ENABLED=0 go build -o "$work/kindcheck" ./scripts/ci/kindcheck)

echo "kind: the cluster and the image"
kind create cluster --name "$cluster" --wait 120s
created=1
docker build -q -t tresor-server:ci --build-arg VERSION=ci "$root" >/dev/null
kind load docker-image tresor-server:ci --name "$cluster"

echo "kind: a CA of this run's, the issuer"
ca_make
issuer_up "$issuer"
ca_cert pg pg.db.svc

echo "kind: PostgreSQL with TLS, its password in a Secret"
kubectl create namespace db
kubectl -n db create secret generic pg-tls --from-file=tls.crt="$work/pg.crt" --from-file=tls.key="$work/pg.key"
pg_password="$(openssl rand -hex 16)"
kubectl -n db create secret generic pg --from-literal=password="$pg_password"
kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: {name: pg, namespace: db}
spec:
  selector: {matchLabels: {app: pg}}
  template:
    metadata: {labels: {app: pg}}
    spec:
      securityContext: {fsGroup: 999}
      containers:
        - name: postgres
          image: postgres:17
          args: [-c, ssl=on, -c, ssl_cert_file=/tls/tls.crt, -c, ssl_key_file=/tls/tls.key]
          env:
            - name: POSTGRES_PASSWORD
              valueFrom: {secretKeyRef: {name: pg, key: password}}
          ports: [{containerPort: 5432}]
          readinessProbe: {exec: {command: [pg_isready, -U, postgres]}, periodSeconds: 2}
          volumeMounts: [{name: tls, mountPath: /tls}]
      volumes:
        - {name: tls, secret: {secretName: pg-tls, defaultMode: 0640}}
---
apiVersion: v1
kind: Service
metadata: {name: pg, namespace: db}
spec:
  selector: {app: pg}
  ports: [{port: 5432}]
EOF
kubectl -n db rollout status deploy/pg --timeout 180s

# install <release> <namespace> <values...>: the chart with the image built here, a local KEK, the run's CA
install() {
	local release="$1" ns="$2"
	shift 2
	kubectl create namespace "$ns"
	kubectl -n "$ns" create secret generic kek --from-literal=key="$(openssl rand -base64 32)"
	kubectl -n "$ns" create configmap ca --from-file=ca.crt="$work/ca.crt"
	cat >"$work/$release.yaml" <<EOF
image: {repository: tresor-server, tag: ci, pullPolicy: Never}
localKEK: {secretName: kek}
env: [{name: SSL_CERT_FILE, value: /etc/tresor-ca/ca.crt}]
extraVolumes: [{name: ca, configMap: {name: ca}}]
extraVolumeMounts: [{name: ca, mountPath: /etc/tresor-ca, readOnly: true}]
resources: {requests: {cpu: 10m, memory: 32Mi}}
config:
  public_url: https://$release.example.com
  issuers:
    - {issuer: $issuer, audience: duckdb-secrets, roles_claim: roles}
  policy: {admins: [role:secrets_admin]}
EOF
	if ! helm install "$release" "$chart" -n "$ns" -f "$work/$release.yaml" "$@" --wait --timeout 180s; then
		kubectl -n "$ns" get pods -o wide || true
		kubectl -n "$ns" logs -l app.kubernetes.io/instance="$release" --tail 50 || true
		exit 1
	fi
}

# smoke <release> <namespace> [<ref> <value>]: through the protocol, by a port-forward on a free local port
smoke() {
	forward "$2" "$1-tresor-server"
	"$work/kindcheck" smoke "$work/idp" "$issuer" "http://127.0.0.1:$port" "${@:3}"
}

echo "kind: an OpenTelemetry collector (spec 005): the audit's log records, the metrics"
kubectl create namespace otel
kubectl -n otel create configmap otelcol --from-literal=config.yaml='receivers:
  otlp: {protocols: {http: {endpoint: 0.0.0.0:4318}}}
exporters:
  debug: {verbosity: detailed}
service:
  pipelines:
    logs: {receivers: [otlp], exporters: [debug]}
    metrics: {receivers: [otlp], exporters: [debug]}
    traces: {receivers: [otlp], exporters: [debug]}'
kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: {name: otelcol, namespace: otel}
spec:
  selector: {matchLabels: {app: otelcol}}
  template:
    metadata: {labels: {app: otelcol}}
    spec:
      containers:
        - name: otelcol
          image: otel/opentelemetry-collector:0.140.0
          args: [--config, /conf/config.yaml]
          ports: [{containerPort: 4318}]
          volumeMounts: [{name: conf, mountPath: /conf}]
      volumes: [{name: conf, configMap: {name: otelcol}}]
---
apiVersion: v1
kind: Service
metadata: {name: otelcol, namespace: otel}
spec:
  selector: {app: otelcol}
  ports: [{port: 4318}]
EOF
kubectl -n otel rollout status deploy/otelcol --timeout 180s

echo "kind: the Kubernetes store, ref+k8s from another namespace, the admission policy"
kubectl create namespace data
kubectl -n data create secret generic duckdb-lake --from-literal=secret=from-a-kubernetes-secret
install t tresor --set config.state.kind=kubernetes \
	--set-json 'config.material={"k8s":{"allow":[{"namespace":"data","prefixes":["duckdb-"]}]}}' \
	--set-json 'env=[{"name":"SSL_CERT_FILE","value":"/etc/tresor-ca/ca.crt"},{"name":"OTEL_EXPORTER_OTLP_ENDPOINT","value":"http://otelcol.otel.svc:4318"},{"name":"OTEL_METRIC_EXPORT_INTERVAL","value":"2000"}]'
smoke t tresor ref+k8s://data/duckdb-lake/secret from-a-kubernetes-secret
# the audit reached the collector, with no material in it; the pods' stdout has it as JSON lines too
for _ in $(seq 30); do
	kubectl -n otel logs deploy/otelcol | grep -q "tresor.kind: Str(read)" && break
	sleep 2
done
collected="$(kubectl -n otel logs deploy/otelcol)"
grep -q "tresor.kind: Str(read)" <<<"$collected" || { echo "kind: no audit record reached the collector" >&2; exit 1; }
grep -q "tresor.server.requests" <<<"$collected" || { echo "kind: no metric reached the collector" >&2; exit 1; }
if grep -qE "kind-material|from-a-kubernetes-secret|eu-west" <<<"$collected"; then
	echo "kind: material reached the collector" >&2
	exit 1
fi
stdout="$(kubectl -n tresor logs -l app.kubernetes.io/instance=t --tail 500)"
grep -q '"audit":"tresor-server/1"' <<<"$stdout" || { echo "kind: no audit line on stdout" >&2; exit 1; }
if grep -qE "kind-material|from-a-kubernetes-secret|eu-west" <<<"$stdout"; then
	echo "kind: material reached the pods' log" >&2
	exit 1
fi
echo "kind: the audit on stdout and in the collector, the metrics, no material"
kubectl -n tresor get tresor
# a hand write is refused; the service's own resources stay as written
if kubectl -n tresor apply -f - 2>"$work/denied" <<'EOF'; then
apiVersion: tresor.hugr-lab.io/v1alpha1
kind: TresorKeyring
metadata: {name: forged}
spec: {dataKeyID: x, slot: 1}
EOF
	echo "kind: a hand write was admitted" >&2
	exit 1
fi
grep -q "only tresor-server writes its resources" "$work/denied" || { cat "$work/denied" >&2; exit 1; }
# denied: name the policy (dry runs: admission runs, nothing changes)
denied() {
	if "$@" --dry-run=server >/dev/null 2>"$work/denied"; then
		echo "kind: admitted: $*" >&2
		exit 1
	fi
	grep -q "only tresor-server writes its resources" "$work/denied" || { cat "$work/denied" >&2; exit 1; }
}
denied kubectl -n tresor delete tresorkeyring active
# a rollback is an UPDATE: an older copy put back
kubectl -n tresor get tresorkeyring active -o json >"$work/keyring.json"
denied kubectl -n tresor replace -f "$work/keyring.json"
# the garbage collector deletes minted tokens only; the namespace controller only in a namespace being deleted
denied kubectl -n tresor delete tresorkeyring active --as=system:serviceaccount:kube-system:generic-garbage-collector
denied kubectl -n tresor delete tresorkeyring active --as=system:serviceaccount:kube-system:namespace-controller
echo "kind: the admission policy refuses a hand write, a rollback, and a controller's delete outside its case"

echo "kind: PostgreSQL, its password from a Kubernetes Secret"
install p tresor-pg --set config.state.kind=postgres \
	--set-string "config.state.dsn=host=pg.db.svc user=postgres dbname=postgres sslmode=verify-full sslrootcert=/etc/tresor-ca/ca.crt" \
	--set config.state.auth=password --set config.state.password_ref=ref+k8s://db/pg/password
smoke p tresor-pg

# bao_up <namespace> <value>: an OpenBao in the namespace, TLS of the run's CA at bao.<namespace>.svc:8200; the
# Kubernetes auth method, its role for the release b's ServiceAccount (the audience of the chart's projected token,
# vaultToken) and a policy: the KEK's Transit key, and the KV paths references may read; secret/duckdb/lake holds
# <value>
bao_up() {
	local ns="$1" value="$2"
	ca_cert "$ns" "bao.$ns.svc"
	kubectl create namespace "$ns"
	kubectl -n "$ns" create secret tls bao-tls --cert "$work/$ns.crt" --key "$work/$ns.key"
	kubectl -n "$ns" create configmap bao-conf --from-literal=tls.hcl='listener "tcp" {
  address = "0.0.0.0:8443"
  tls_cert_file = "/tls/tls.crt"
  tls_key_file = "/tls/tls.key"
}'
	sed "s/NAMESPACE/$ns/g" <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata: {name: bao, namespace: NAMESPACE}
---
# the Kubernetes auth method reviews the service's tokens with OpenBao's own
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: NAMESPACE-auth-delegator}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: system:auth-delegator}
subjects: [{kind: ServiceAccount, name: bao, namespace: NAMESPACE}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: bao, namespace: NAMESPACE}
spec:
  selector: {matchLabels: {app: bao}}
  template:
    metadata: {labels: {app: bao}}
    spec:
      serviceAccountName: bao
      containers:
        - name: openbao
          image: openbao/openbao:2.4.1
          # a dev server (in memory, unsealed, root token "root" on plain http, kept to the pod's loopback; the image's
          # entrypoint would put it on 0.0.0.0, the last flag wins) with a TLS listener of the run's CA
          args: [server, -dev, -dev-root-token-id=root, -dev-listen-address=127.0.0.1:8200, -config=/conf/tls.hcl]
          ports: [{containerPort: 8443}]
          readinessProbe: {httpGet: {path: /v1/sys/health, port: 8443, scheme: HTTPS}, periodSeconds: 2}
          volumeMounts:
            - {name: conf, mountPath: /conf}
            - {name: tls, mountPath: /tls}
      volumes:
        - {name: conf, configMap: {name: bao-conf}}
        - {name: tls, secret: {secretName: bao-tls}}
---
apiVersion: v1
kind: Service
metadata: {name: bao, namespace: NAMESPACE}
spec:
  selector: {app: bao}
  ports: [{port: 8200, targetPort: 8443}]
EOF
	kubectl -n "$ns" rollout status deploy/bao --timeout 180s || { baodump "$ns"; exit 1; }
	kubectl -n "$ns" exec -i deploy/bao -- env BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root VALUE="$value" sh -eu >/dev/null <<'EOF' || { baodump "$ns"; exit 1; }
bao auth enable kubernetes
bao write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc
bao policy write tresor - <<'HCL'
path "transit/keys/kek"           { capabilities = ["read"] }
path "transit/encrypt/kek"        { capabilities = ["update"] }
path "transit/decrypt/kek"        { capabilities = ["update"] }
path "transit/hmac/kek/sha2-256"  { capabilities = ["update"] }
path "secret/data/duckdb/*"       { capabilities = ["read"] }
HCL
bao write auth/kubernetes/role/tresor bound_service_account_names=b-tresor-server,m-tresor-server \
  bound_service_account_namespaces=tresor-bao,tresor-move audience=vault token_policies=tresor token_ttl=1h
bao secrets enable transit
bao write -f transit/keys/kek type=aes256-gcm96
bao kv put secret/duckdb/lake secret="$VALUE"
EOF
}
baodump() {
	kubectl -n "$1" get pods -o wide || true
	kubectl -n "$1" logs deploy/bao --tail 50 || true
}

echo "kind: OpenBao with Kubernetes auth (spec 007): the KEK in Transit, ref+vault, the Kubernetes store; a second"
echo "kind: OpenBao as a named source (spec 008), ref+bao2"
bao_up bao from-openbao
bao_up bao2 from-the-second-openbao
install b tresor-bao --set config.state.kind=kubernetes --set localKEK.secretName= --set vaultToken.enabled=true \
	--set-json 'config.keys={"kind":"vault","key":"kek"}' \
	--set-json 'config.vault={"address":"https://bao.bao.svc:8200","ca_file":"/etc/tresor-ca/ca.crt","auth":{"method":"kubernetes","role":"tresor"}}' \
	--set-json 'config.material={"vault":{"allow":[{"mount":"secret","prefixes":["duckdb/"]}]},"sources":[{"name":"bao2","kind":"vault","vault":{"address":"https://bao.bao2.svc:8200","ca_file":"/etc/tresor-ca/ca.crt","auth":{"method":"kubernetes","role":"tresor"}},"allow":[{"mount":"secret","prefixes":["duckdb/"]}]}]}'
smoke b tresor-bao 'ref+vault://secret/duckdb/lake#secret' from-openbao
smoke b tresor-bao 'ref+bao2://secret/duckdb/lake#secret' from-the-second-openbao
kek="$(kubectl -n tresor-bao get tresordatakeys -o jsonpath='{.items[*].spec.kekID}')"
[[ "$kek" == vault:transit/kek:v1* ]] || { echo "kind: the data keys are not under the Transit KEK: $kek" >&2; exit 1; }
# no material in the pods' log (not through a pipe: grep -q's early exit would fail it under pipefail)
stdout="$(kubectl -n tresor-bao logs -l app.kubernetes.io/instance=b --tail 500)"
if grep -qE "from-openbao|from-the-second-openbao" <<<"$stdout"; then
	echo "kind: material reached the pods' log" >&2
	exit 1
fi
echo "kind: OpenBao: logged in by Kubernetes auth, data keys under Transit, ref+vault read; ref+bao2 from the second"

echo "kind: a move to another KEK (spec 011): local -> OpenBao Transit, the old one previous, rewrap, then alone"
install m tresor-move --set config.state.kind=kubernetes
forward tresor-move m-tresor-server
"$work/kindcheck" keep "$work/idp" "$issuer" "http://127.0.0.1:$port"
move() {
	if ! helm upgrade m "$chart" -n tresor-move -f "$work/m.yaml" --set config.state.kind=kubernetes --set localKEK.secretName= \
		--set vaultToken.enabled=true --set-json 'config.keys={"kind":"vault","key":"kek"}' \
		--set-json 'config.vault={"address":"https://bao.bao.svc:8200","ca_file":"/etc/tresor-ca/ca.crt","auth":{"method":"kubernetes","role":"tresor"}}' \
		"$@" --wait --timeout 180s; then
		kubectl -n tresor-move logs -l app.kubernetes.io/instance=m --tail 50 || true
		exit 1
	fi
	kubectl -n tresor-move rollout status deploy/m-tresor-server --timeout 120s
}
move --set localKEK.previousSecretName=kek
forward tresor-move m-tresor-server
"$work/kindcheck" kept "$work/idp" "$issuer" "http://127.0.0.1:$port"
kubectl -n tresor-move exec deploy/m-tresor-server -- /tresor-server rewrap -config /etc/tresor/server.yaml
kek="$(kubectl -n tresor-move get tresordatakeys -o jsonpath='{range .items[*]}{.spec.kekID}{"\n"}{end}')"
if grep -qv '^vault:transit/kek:v' <<<"$kek"; then
	echo "kind: a data key is still under the old KEK after rewrap: $kek" >&2
	exit 1
fi
move --set localKEK.previousSecretName=
forward tresor-move m-tresor-server
"$work/kindcheck" kept "$work/idp" "$issuer" "http://127.0.0.1:$port"
echo "kind: the KEK moved: read under the old KEK as previous, rewrapped, read under OpenBao alone"

echo "kind: Keycloak's federated client authentication (spec 006): the service's exchange client logged in by its"
echo "kind: projected ServiceAccount token, a Kubernetes identity provider in Keycloak - no client secret"
kc_admin_secret="$(openssl rand -hex 16)"
kc_caller_secret="$(openssl rand -hex 16)"
kc_issuer=https://keycloak.kc.svc:8443/realms/tresor
ca_cert kc keycloak.kc.svc
kubectl create namespace kc
kubectl -n kc create secret tls kc-tls --cert "$work/kc.crt" --key "$work/kc.key"
KC_ADMIN_SECRET="$kc_admin_secret" KC_CALLER_SECRET="$kc_caller_secret" python3 - "$work/realm.json" <<'PY'
import json, os, sys
aud = lambda name, audience: {"name": name, "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                              "config": {"included.client.audience": audience, "access.token.claim": "true"}}
caller = lambda cid, secret: {"clientId": cid, "secret": secret, "publicClient": False, "standardFlowEnabled": False,
                              "serviceAccountsEnabled": True, "protocolMappers": [aud("aud", "duckdb-secrets")]}
realm = {
    "realm": "tresor", "enabled": True,
    "roles": {"realm": [{"name": "secrets_admin"}, {"name": "analysts"}]},
    # the cluster's service-account issuer: Keycloak reads its keys with its own ServiceAccount token
    "identityProviders": [{"alias": "k8s", "providerId": "kubernetes", "enabled": True,
                           "config": {"issuer": "https://kubernetes.default.svc.cluster.local"}}],
    "clients": [
        # the service's exchange client: no secret, its ServiceAccount's token is its credential
        {"clientId": "duckdb-secrets", "publicClient": False, "standardFlowEnabled": False, "serviceAccountsEnabled": False,
         "clientAuthenticatorType": "federated-jwt",
         "attributes": {"jwt.credential.issuer": "k8s", "jwt.credential.sub": "system:serviceaccount:tresor-kc:k-tresor-server",
                        "standard.token.exchange.enabled": "true"},
         "protocolMappers": [aud("aud", "lake-api")]},
        caller("ci-admin", os.environ["KC_ADMIN_SECRET"]),
        caller("ci-caller", os.environ["KC_CALLER_SECRET"]),
        {"clientId": "lake-api", "publicClient": False, "standardFlowEnabled": False},
    ],
    "users": [
        {"username": "service-account-ci-admin", "enabled": True, "serviceAccountClientId": "ci-admin", "realmRoles": ["secrets_admin"]},
        {"username": "service-account-ci-caller", "enabled": True, "serviceAccountClientId": "ci-caller", "realmRoles": ["analysts"]},
    ],
}
json.dump(realm, open(sys.argv[1], "w"))
PY
kubectl -n kc create secret generic kc-realm --from-file=realm.json="$work/realm.json"
rm -f "$work/realm.json"
kubectl apply -f - <<'YAML'
apiVersion: v1
kind: ServiceAccount
metadata: {name: keycloak, namespace: kc}
---
# Keycloak reads the cluster's service-account issuer (discovery, keys) with its own token
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: kc-issuer-discovery}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: system:service-account-issuer-discovery}
subjects: [{kind: ServiceAccount, name: keycloak, namespace: kc}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: keycloak, namespace: kc}
spec:
  selector: {matchLabels: {app: keycloak}}
  template:
    metadata: {labels: {app: keycloak}}
    spec:
      serviceAccountName: keycloak
      containers:
        - name: keycloak
          image: quay.io/keycloak/keycloak:26.6.4
          args: [start-dev, --import-realm, --https-port=8443, --https-certificate-file=/tls/tls.crt,
                 --https-certificate-key-file=/tls/tls.key, --hostname=https://keycloak.kc.svc:8443,
                 --truststore-paths=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt]
          ports: [{containerPort: 8443}]
          readinessProbe: {httpGet: {path: /realms/tresor, port: 8443, scheme: HTTPS}, periodSeconds: 5, failureThreshold: 60}
          resources: {requests: {cpu: 100m, memory: 512Mi}}
          volumeMounts:
            - {name: tls, mountPath: /tls, readOnly: true}
            - {name: realm, mountPath: /opt/keycloak/data/import, readOnly: true}
      volumes:
        - {name: tls, secret: {secretName: kc-tls}}
        - {name: realm, secret: {secretName: kc-realm}}
---
apiVersion: v1
kind: Service
metadata: {name: keycloak, namespace: kc}
spec: {selector: {app: keycloak}, ports: [{port: 8443, targetPort: 8443}]}
YAML
if ! kubectl -n kc rollout status deploy/keycloak --timeout 300s; then
	kubectl -n kc logs deploy/keycloak --tail 80 || true
	exit 1
fi
install k tresor-kc --set config.state.kind=kubernetes \
	--set exchangeToken.enabled=true --set exchangeToken.audience="$kc_issuer" --set exchangeToken.expirationSeconds=600 \
	--set-json 'config.issuers=[{"issuer":"'"$kc_issuer"'","audience":"duckdb-secrets","roles_claim":"realm_access.roles","exchange":{"client_id":"duckdb-secrets","client_auth":"file","assertion_file":"/var/run/tresor/idp-token/token","omit_client_id":true}}]'
forward tresor-kc k-tresor-server
tresor_port="$port"
kubectl -n kc port-forward svc/keycloak :8443 >"$work/kc.forward" &
pids+=($!)
kc_port=""
for _ in $(seq 30); do
	kc_port="$(sed -n 's/^Forwarding from 127.0.0.1:\([0-9]*\) .*/\1/p' "$work/kc.forward" | head -1)"
	[ -n "$kc_port" ] && curl -sf --cacert "$work/ca.crt" --resolve "keycloak.kc.svc:$kc_port:127.0.0.1" \
		"https://keycloak.kc.svc:$kc_port/realms/tresor" >/dev/null && break
	sleep 1
done
[ -n "$kc_port" ] || { echo "kind: Keycloak is not reachable behind a port-forward" >&2; cat "$work/kc.forward" >&2; exit 1; }
if ! KC_ADMIN_SECRET="$kc_admin_secret" KC_CALLER_SECRET="$kc_caller_secret" \
	"$work/kindcheck" kc "$work/ca.crt" "https://127.0.0.1:$kc_port" "http://127.0.0.1:$tresor_port"; then
	kubectl -n kc logs deploy/keycloak --tail 60 | grep -iE "warn|error|client" || true
	kubectl -n tresor-kc logs -l app.kubernetes.io/instance=k --tail 40 || true
	exit 1
fi
echo "kind: Keycloak minted by exchange, the service authenticated by its ServiceAccount token"

echo "kind: the Kubernetes store's namespace deleted: the namespace controller deletes its resources"
# the policy stays (cluster-scoped): a namespace that would not delete would hang here
kubectl delete namespace tresor --timeout 120s
echo "kind: passed"
