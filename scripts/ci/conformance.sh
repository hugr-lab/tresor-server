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
(cd "$root" && GOWORK=off CGO_ENABLED=0 go build -o "$work/tresor-server" ./cmd/tresor-server)
sed -e "s/^  kind: memory$/  kind: $kind/" "$root/testdata/keycloak/server.yaml" >"$work/server.yaml"
grep -q "^  kind: $kind$" "$work/server.yaml" || {
	echo "conformance: the config template names no state kind to replace" >&2
	exit 1
}

# one simple command that is the server (test_keycloak.sh runs it with exec): the config it names is the one
# test_keycloak.sh writes on this run's ports
export TRESOR_SERVER_CMD="$work/tresor-server -config \"\$TRESOR_TEST_SERVER_CONFIG\""
export TRESOR_SERVER_CONFIG="$work/server.yaml"
export TRESOR_SERVER_WAIT="${TRESOR_SERVER_WAIT:-30}"
echo "conformance: tresor-server on state $kind"
"$tresor/scripts/ci/test_keycloak.sh" "$tresor/build/release/test/unittest"
