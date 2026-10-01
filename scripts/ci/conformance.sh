#!/usr/bin/env bash
# tresor's conformance suite and its reference server's tests against tresor-server (spec 002): tresor's own
# scripts/ci/test_keycloak.sh starts Keycloak, seeds the secrets through the protocol and runs the tests, with
# this service in place of ref-server (TRESOR_SERVER_CMD). Needs docker, go, python3, and a tresor checkout
# with its build (build/release: unittest, duckdb, the tresor extension).
#
#   scripts/ci/conformance.sh <tresor dir> [state kind]     # the kind defaults to memory
#
# kubernetes needs KUBEBUILDER_ASSETS: envtest's binaries (setup-envtest use -p path).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
tresor="$(cd "${1:?usage: conformance.sh <tresor dir> [state kind]}" && pwd)"
kind="${2:-memory}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

[ -x "$tresor/build/release/test/unittest" ] || {
	echo "conformance: no tresor build in $tresor/build/release" >&2
	exit 1
}
(cd "$root" && GOWORK=off CGO_ENABLED=0 go build -o "$work/tresor-server" ./cmd/tresor-server &&
	GOWORK=off CGO_ENABLED=0 go build -o "$work/replicas" ./scripts/ci/replicas &&
	GOWORK=off CGO_ENABLED=0 go build -o "$work/testdb" ./scripts/ci/testdb &&
	GOWORK=off CGO_ENABLED=0 go build -o "$work/kubeenv" ./scripts/ci/kubeenv)

# one simple command that is the server (test_keycloak.sh runs it with exec): the config it names is the one
# test_keycloak.sh writes on this run's ports
printf -v bin '%q' "$work/tresor-server"
export TRESOR_SERVER_CMD="$bin -config \"\$TRESOR_TEST_SERVER_CONFIG\""
replicas="${TRESOR_CONFORMANCE_REPLICAS:-1}"
if [ "$replicas" -gt 1 ]; then
	# several replicas behind a round-robin proxy, as one foreground command: a grant made on one is used on
	# another, a token renewed on one is read by the other
	printf -v proxy '%q' "$work/replicas"
	export TRESOR_SERVER_CMD="$proxy -n $replicas -config \"\$TRESOR_TEST_SERVER_CONFIG\" $bin"
fi
export TRESOR_SERVER_CONFIG="$root/testdata/keycloak/server.yaml"
# the store from the environment, over the file's (spec 002: configuration from the environment)
export TRESOR_STATE__KIND="$kind"
export TRESOR_SERVER_WAIT="${TRESOR_SERVER_WAIT:-30}"
case "$kind" in
memory) ;;
postgres | sqlserver)
	# TRESOR_TEST_POSTGRES / TRESOR_TEST_SQLSERVER: the server's admin DSN, no password in it (the password in
	# TRESOR_TEST_POSTGRES_PASSWORD / TRESOR_TEST_SQLSERVER_PASSWORD); a database of this run's is made there,
	# and dropped after. A local KEK made for the run
	upper="$(echo "$kind" | tr a-z A-Z)"
	admin_var="TRESOR_TEST_$upper" password_var="TRESOR_TEST_${upper}_PASSWORD"
	db_admin="${!admin_var:-}"
	[ -n "$db_admin" ] || {
		echo "conformance: $admin_var names no server" >&2
		exit 1
	}
	db_run="$("$work/testdb" create "$kind" "$db_admin")"
	trap '"$work/testdb" drop "$kind" "$db_admin" "$db_run" || true; rm -rf "$work"' EXIT
	export TRESOR_STATE__DSN="$db_run" TRESOR_STATE__AUTH=password TRESOR_STATE__PASSWORD_ENV="$password_var"
	export TRESOR_KEYS__KIND=local TRESOR_KEYS__KEY_ENV=TRESOR_TEST_KEK
	TRESOR_TEST_KEK="$(openssl rand -base64 32)"
	export TRESOR_TEST_KEK
	;;
sqlite)
	# a database of this run's, sealed under a local KEK made for it
	export TRESOR_STATE__PATH="$work/tresor.db" TRESOR_KEYS__KIND=local TRESOR_KEYS__KEY_ENV=TRESOR_TEST_KEK
	TRESOR_TEST_KEK="$(openssl rand -base64 32)"
	export TRESOR_TEST_KEK
	;;
kubernetes)
	# an API server of this run's (envtest: KUBEBUILDER_ASSETS from setup-envtest) with the chart's CRDs; the
	# replicas reach it by KUBECONFIG, as outside a pod. A local KEK made for the run
	"$work/kubeenv" up "$root/deploy/helm/tresor-server/crds" "$work/kubeconfig" tresor >"$work/kubeenv.log" 2>&1 &
	kubeenv_pid=$!
	trap 'kill "$kubeenv_pid" 2>/dev/null; wait "$kubeenv_pid" 2>/dev/null; rm -rf "$work"' EXIT
	for _ in $(seq 120); do
		[ -f "$work/kubeconfig" ] && break
		kill -0 "$kubeenv_pid" 2>/dev/null || break
		sleep 0.5
	done
	[ -f "$work/kubeconfig" ] || {
		echo "conformance: the API server did not start" >&2
		cat "$work/kubeenv.log" >&2
		exit 1
	}
	export KUBECONFIG="$work/kubeconfig" TRESOR_STATE__NAMESPACE=tresor
	export TRESOR_KEYS__KIND=local TRESOR_KEYS__KEY_ENV=TRESOR_TEST_KEK
	TRESOR_TEST_KEK="$(openssl rand -base64 32)"
	export TRESOR_TEST_KEK
	;;
*)
	echo "conformance: no setup for state $kind" >&2
	exit 1
	;;
esac
echo "conformance: tresor-server on state $kind, $replicas replica(s)"
status=0
"$tresor/scripts/ci/test_keycloak.sh" "$tresor/build/release/test/unittest" || status=$?
if [ "$kind" = sqlite ]; then
	# the material test_keycloak.sh seeded (s3cr3t) was written - and is sealed at rest
	[ -s "$work/tresor.db" ] || {
		echo "conformance: no SQLite database was written" >&2
		status=1
	}
	for f in "$work/tresor.db" "$work/tresor.db-wal"; do
		if [ -f "$f" ] && grep -aq 's3cr3t' "$f"; then
			echo "conformance: $(basename "$f") holds the seeded material in the clear" >&2
			status=1
		fi
	done
	[ "$status" = 0 ] && echo "conformance: the SQLite database holds no material in the clear"
fi
if [ "$kind" = postgres ] || [ "$kind" = sqlserver ]; then
	if "$work/testdb" clear "$kind" "$db_run" s3cr3t; then
		echo "conformance: the $kind database holds no material in the clear"
	else
		status=1
	fi
fi
if [ "$kind" = kubernetes ]; then
	"$work/kubeenv" clear "$work/kubeconfig" tresor s3cr3t || status=1
fi
exit "$status"
