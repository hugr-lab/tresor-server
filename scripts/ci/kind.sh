#!/usr/bin/env bash
# The chart on a real cluster (spec 003): kind, the image built here, an OIDC issuer and a PostgreSQL behind a
# CA of this run's. Two installs:
#   - the Kubernetes store, the admission policy refusing a hand write and letting the garbage collector
#     delete;
#   - PostgreSQL in the cluster, its password from a Kubernetes Secret (state.password_ref: ref+k8s).
# Each is checked through the protocol (scripts/ci/kindcheck). Needs docker, kind, kubectl, helm, go, openssl.
#
#   scripts/ci/kind.sh            # TRESOR_KIND_KEEP=1 keeps the cluster afterwards
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cluster="${TRESOR_KIND_CLUSTER:-tresor-ci}"
work="$(mktemp -d)"
pids=()
cleanup() {
	for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null || true; done
	if [ -z "${TRESOR_KIND_KEEP:-}" ]; then kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
	rm -rf "$work"
}
trap cleanup EXIT
chart="$root/deploy/helm/tresor-server"
issuer=https://idp.idp.svc/realms/t
kubectl() { command kubectl --context "kind-$cluster" "$@"; }
helm() { command helm --kube-context "kind-$cluster" "$@"; }
(cd "$root" && GOWORK=off CGO_ENABLED=0 go build -o "$work/kindcheck" ./scripts/ci/kindcheck)

echo "kind: the cluster and the image"
kind create cluster --name "$cluster" --wait 120s
docker build -q -t tresor-server:ci --build-arg VERSION=ci "$root" >/dev/null
kind load docker-image tresor-server:ci --name "$cluster"

echo "kind: a CA of this run's, the issuer's and the database's certificates"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/ca.key" -out "$work/ca.crt" -days 1 -subj /CN=tresor-ci-ca 2>/dev/null
cert() { # name dns
	openssl req -newkey rsa:2048 -nodes -keyout "$work/$1.key" -out "$work/$1.csr" -subj "/CN=$2" 2>/dev/null
	printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$2" >"$work/$1.ext"
	openssl x509 -req -in "$work/$1.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial -days 1 \
		-extfile "$work/$1.ext" -out "$work/$1.crt" 2>/dev/null
}
cert idp idp.idp.svc
cert pg pg.db.svc

echo "kind: the issuer (nginx, static discovery and JWKS)"
"$work/kindcheck" issuer "$work/idp" "$issuer"
kubectl create namespace idp
kubectl -n idp create secret tls idp-tls --cert "$work/idp.crt" --key "$work/idp.key"
kubectl -n idp create configmap idp-files --from-file="$work/idp/openid-configuration" --from-file="$work/idp/jwks"
kubectl -n idp create configmap idp-nginx --from-literal=default.conf='server {
  listen 8443 ssl;
  ssl_certificate /tls/tls.crt;
  ssl_certificate_key /tls/tls.key;
  default_type application/json;
  location = /realms/t/.well-known/openid-configuration { alias /files/openid-configuration; }
  location = /realms/t/jwks { alias /files/jwks; }
}'
kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: {name: idp, namespace: idp}
spec:
  selector: {matchLabels: {app: idp}}
  template:
    metadata: {labels: {app: idp}}
    spec:
      containers:
        - name: nginx
          image: nginxinc/nginx-unprivileged:1.29-alpine
          ports: [{containerPort: 8443}]
          volumeMounts:
            - {name: conf, mountPath: /etc/nginx/conf.d}
            - {name: files, mountPath: /files}
            - {name: tls, mountPath: /tls}
      volumes:
        - {name: conf, configMap: {name: idp-nginx}}
        - {name: files, configMap: {name: idp-files}}
        - {name: tls, secret: {secretName: idp-tls}}
---
apiVersion: v1
kind: Service
metadata: {name: idp, namespace: idp}
spec:
  selector: {app: idp}
  ports: [{port: 443, targetPort: 8443}]
EOF

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
kubectl -n idp rollout status deploy/idp --timeout 180s
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
  tls: {offload: true}
  keys: {kind: local, key_file: /var/run/tresor/kek/key}
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

# smoke <release> <namespace>: through the protocol, by a port-forward on a free local port
smoke() {
	kubectl -n "$2" port-forward "svc/$1-tresor-server" :80 >"$work/$1.forward" &
	pids+=($!)
	local port=""
	for _ in $(seq 30); do
		port="$(sed -n 's/^Forwarding from 127.0.0.1:\([0-9]*\) .*/\1/p' "$work/$1.forward" | head -1)"
		[ -n "$port" ] && curl -sf "http://127.0.0.1:$port/readyz" >/dev/null && break
		sleep 1
	done
	"$work/kindcheck" smoke "$work/idp" "$issuer" "http://127.0.0.1:$port"
}

echo "kind: the Kubernetes store, the admission policy"
install t tresor --set config.state.kind=kubernetes
smoke t tresor
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
if kubectl -n tresor delete tresorkeyring active --dry-run=server 2>/dev/null; then
	echo "kind: a hand delete was admitted" >&2
	exit 1
fi
# the garbage collector and the namespace controller may delete (a dry run: admission runs, nothing goes)
kubectl -n tresor delete tresorkeyring active --dry-run=server \
	--as=system:serviceaccount:kube-system:generic-garbage-collector
kubectl -n tresor delete tresorkeyring active --dry-run=server \
	--as=system:serviceaccount:kube-system:namespace-controller
echo "kind: the admission policy refuses a hand write and lets the garbage collector delete"

echo "kind: PostgreSQL, its password from a Kubernetes Secret"
install p tresor-pg --set config.state.kind=postgres \
	--set-string "config.state.dsn=host=pg.db.svc user=postgres dbname=postgres sslmode=verify-full sslrootcert=/etc/tresor-ca/ca.crt" \
	--set config.state.auth=password --set config.state.password_ref=ref+k8s://db/pg/password
smoke p tresor-pg
echo "kind: passed"
