#!/usr/bin/env bash
# The docs' versions (spec 035), made at deploy time from the release tags: each v<X.Y.Z> from DOCS_FIRST_VERSION
# on (pre-releases skipped) has its website/docs and sidebars snapshotted as version X.Y.Z - the same
# `docs:version` a maintainer would run on the tag's tree. Nothing is committed: versions.json, versioned_docs/
# and versioned_sidebars/ are gitignored. Run from anywhere; needs the tags (fetch-depth: 0) and website's npm ci.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
first="${DOCS_FIRST_VERSION:-0.8.0}"   # older releases' docs are not published as versions
cd "$root"
rm -rf website/versioned_docs website/versioned_sidebars website/versions.json
for tag in $(git tag --list 'v*' | sort -V); do
	case "$tag" in *-*) continue ;; esac
	ver="${tag#v}"
	[ "$(printf '%s\n%s\n' "$first" "$ver" | sort -V | head -1)" = "$first" ] || continue
	[ -n "$(git ls-tree -d --full-tree "$tag" -- website/docs)" ] || { echo "docs_versions: $tag has no website/docs"; continue; }
	snap="$(mktemp -d)"
	git archive --format=tar "$tag" website/docs website/sidebars.ts | tar -x -C "$snap"
	mv website/docs website/docs.next && mv "$snap/website/docs" website/docs
	cp website/sidebars.ts website/sidebars.next.ts && cp "$snap/website/sidebars.ts" website/sidebars.ts
	(cd website && npx docusaurus docs:version "$ver" >/dev/null)
	rm -rf website/docs && mv website/docs.next website/docs
	mv website/sidebars.next.ts website/sidebars.ts
	rm -rf "$snap"
	echo "docs_versions: $tag as $ver"
done
cat website/versions.json 2>/dev/null || echo "docs_versions: no release yet - the current docs are the only version"
