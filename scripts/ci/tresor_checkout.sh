#!/usr/bin/env bash
# tresor at the commit this service's conformance runs against (spec 002): its conformance suite, its
# reference server's tests, and scripts/ci/test_keycloak.sh with the TRESOR_SERVER_CMD hook (tresor #22).
# Move TRESOR_COMMIT to take a newer suite; the CI cache of tresor's build is keyed on this file.
#
#   scripts/ci/tresor_checkout.sh <dir> [--submodules]    # --submodules: to build it (duckdb, ...)
set -euo pipefail
TRESOR_COMMIT=7fa19cbe5d12a7b5c9000255cf9c211db626f78f # tresor main: spec 016 - names a service may refuse, service_error (#26)
root="$(cd "$(dirname "$0")/../.." && pwd)"
dest="${1:?usage: tresor_checkout.sh <dir> [--submodules]}"

# a directory of its own: never the working tree, its parent or /
case "$(cd "$(dirname "$dest")" 2>/dev/null && pwd)/$(basename "$dest")" in
"$root" | "$root/." | "$(dirname "$root")" | / | //)
	echo "tresor_checkout: refusing to replace $dest" >&2
	exit 1
	;;
esac
rm -rf "$dest"
git init -q "$dest"
git -C "$dest" remote add origin https://github.com/hugr-lab/tresor
git -C "$dest" fetch -q --depth 1 origin "$TRESOR_COMMIT"
git -C "$dest" checkout -q FETCH_HEAD
if [ "${2:-}" = "--submodules" ]; then
	git -C "$dest" submodule update -q --init --recursive --depth 1
fi
echo "tresor_checkout: tresor $TRESOR_COMMIT in $dest"
