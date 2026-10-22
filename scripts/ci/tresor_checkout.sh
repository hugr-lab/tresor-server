#!/usr/bin/env bash
# tresor at the commit this service's conformance runs against (spec 002): its conformance suite, its
# reference server's tests, and scripts/ci/test_keycloak.sh with the TRESOR_SERVER_CMD hook (tresor #22).
# Move TRESOR_COMMIT to take a newer suite; the CI cache of tresor's build is keyed on this file.
#
#   scripts/ci/tresor_checkout.sh <dir> [--submodules]    # --submodules: to build it (duckdb, ...)
set -euo pipefail
TRESOR_COMMIT=594fccaba5b596e8f2bb2e0b52bbb41f35993db8 # tresor main after v0.1.0: specs 040, 041
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
