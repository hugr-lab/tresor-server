#!/usr/bin/env bash
# The chart on a real cluster (spec 003): kind, the image built here, an OIDC issuer and a PostgreSQL behind a
# CA of this run's. Three installs:
#   - the Kubernetes store, the admission policy refusing a hand write and letting the garbage collector
#     delete;
#   - PostgreSQL in the cluster, its password from a Kubernetes Secret (state.password_ref: ref+k8s).
#   - OpenBao in the cluster: Kubernetes auth with a projected token, the KEK in Transit, ref+vault, the
#     Kubernetes store; a second OpenBao as a named source (ref+bao2).
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
bao write auth/kubernetes/role/tresor bound_service_account_names=b-tresor-server \
  bound_service_account_namespaces=tresor-bao audience=vault token_policies=tresor token_ttl=1h
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

echo "kind: the Kubernetes store's namespace deleted: the namespace controller deletes its resources"
# the policy stays (cluster-scoped): a namespace that would not delete would hang here
kubectl delete namespace tresor --timeout 120s
echo "kind: passed"
