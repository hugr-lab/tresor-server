# In-cluster test fixtures (sourced by scripts/ci/kind.sh and scripts/dev/aks_live.sh), not shipped: a CA of the
# run's and an OIDC issuer (nginx serving static discovery and a JWKS, made by kindcheck). Needs: work (a temp
# dir with kindcheck built in it), pids (an array), and a kubectl that reaches the cluster (a function or the
# binary; KUBECTL_CONTEXT names its context, if any).

# ca_make: a CA of this run's in $work/ca.{crt,key}
ca_make() {
	openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/ca.key" -out "$work/ca.crt" -days 1 -subj /CN=tresor-ci-ca 2>/dev/null
}

# ca_cert <name> <dns>: a server certificate in $work/<name>.{crt,key}
ca_cert() {
	openssl req -newkey rsa:2048 -nodes -keyout "$work/$1.key" -out "$work/$1.csr" -subj "/CN=$2" 2>/dev/null
	printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$2" >"$work/$1.ext"
	openssl x509 -req -in "$work/$1.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial -days 1 \
		-extfile "$work/$1.ext" -out "$work/$1.crt" 2>/dev/null
}

# issuer_up <issuer>: the issuer at https://idp.idp.svc/realms/t, its key in $work/idp
issuer_up() {
	ca_cert idp idp.idp.svc
	"$work/kindcheck" issuer "$work/idp" "$1"
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
	kubectl -n idp rollout status deploy/idp --timeout 180s
}

# forward <namespace> <service>: a port-forward on a free local port, its pid in pids, the port in port (not
# in a subshell: the pid must reach pids)
forward() {
	local out="$work/$2.forward"
	port=""
	command kubectl ${KUBECTL_CONTEXT:+--context "$KUBECTL_CONTEXT"} -n "$1" port-forward "svc/$2" :80 >"$out" &
	pids+=($!)
	for _ in $(seq 30); do
		port="$(sed -n 's/^Forwarding from 127.0.0.1:\([0-9]*\) .*/\1/p' "$out" | head -1)"
		[ -n "$port" ] && curl -sf "http://127.0.0.1:$port/readyz" >/dev/null && return 0
		sleep 1
	done
	echo "forward: $1/$2 is not ready behind a port-forward" >&2
	cat "$out" >&2
	return 1
}
