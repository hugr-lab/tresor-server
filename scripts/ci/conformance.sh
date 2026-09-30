#!/usr/bin/env bash
# tresor's conformance suite and its reference server's tests against tresor-server (spec 002): tresor's own
# scripts/ci/test_keycloak.sh starts Keycloak, seeds the secrets through the protocol and runs the tests, with
# this service in place of ref-server (TRESOR_SERVER_CMD). Needs docker, go, python3, and a tresor checkout
# with its build (build/release: unittest, duckdb, the tresor extension).
#
#   scripts/ci/conformance.sh <tresor dir> [state kind]     # the kind defaults to memory
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
	GOWORK=off CGO_ENABLED=0 go build -o "$work/pgdb" ./scripts/ci/pgdb)

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
postgres)
	# TRESOR_TEST_POSTGRES: the server's admin DSN, no password in it (the password in
	# TRESOR_TEST_POSTGRES_PASSWORD); a database of this run's is made there, and dropped after. A local
	# KEK made for the run
	[ -n "${TRESOR_TEST_POSTGRES:-}" ] || {
		echo "conformance: TRESOR_TEST_POSTGRES names no server" >&2
		exit 1
	}
	pg_run="$("$work/pgdb" create "$TRESOR_TEST_POSTGRES")"
	trap '"$work/pgdb" drop "$TRESOR_TEST_POSTGRES" "$pg_run" || true; rm -rf "$work"' EXIT
	export TRESOR_STATE__DSN="$pg_run" TRESOR_STATE__AUTH=password
	export TRESOR_STATE__PASSWORD_ENV=TRESOR_TEST_POSTGRES_PASSWORD
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
if [ "$kind" = postgres ]; then
	if "$work/pgdb" clear "$pg_run" s3cr3t; then
		echo "conformance: the PostgreSQL database holds no material in the clear"
	else
		status=1
	fi
fi
exit "$status"
