# Spec 035: versioned docs

- **Status**: accepted (the owner, 2026-10-26: "давай сделаем документацию версионированной")
- **Date**: 2026-10-26
- **Author**: hugr lab

## Summary

The docs site shows the latest release at its root and main's docs as "Next" under `/next/`; older releases stay
reachable from a version dropdown. Only the latest release is indexed (the owner's decision, 2026-10-26, for every
hugr-lab docs site; tresor#82).

## Design

- **Versions from the tags, at deploy time** (as tresor): the Pages workflow fetches the tags and
  `scripts/ci/docs_versions.sh` snapshots each `v<X.Y.Z>` (no pre-release) from **0.8.0** on - its `website/docs`
  and `sidebars.ts`, through `docusaurus docs:version`. `versions.json`, `versioned_docs/` and
  `versioned_sidebars/` are gitignored: the tag is the snapshot. A main push changes `/next/`; a tag's push runs the
  workflow and moves the root. Older releases' docs (0.1-0.7) are not published as versions: they described a
  service that has moved on (`DOCS_FIRST_VERSION`).
- **Indexing**: `docs.versions` gives `current` (Next) and every release but the latest `noIndex` - Docusaurus emits
  `noindex, nofollow` and leaves them out of the sitemap. Without `versions.json` (a pull request's build,
  docs-build.yml) the current docs are the only version and are indexed as before.
- **Navigation**: a version dropdown in the navbar when there are versions; Next carries Docusaurus's "unreleased"
  banner.
- **Both builds** (GitHub Pages and the hugr-lab.com copy) carry the versions: the snapshot runs before them.
- Development: how a release publishes its docs, and how to see the versioned site locally.

## Testing

Locally with the v0.8.0 tag: the root is 0.8.0 (no robots meta), `/next/` has `noindex, nofollow` and the banner,
the sitemap has no `/next/` page, the dropdown lists Next and 0.8.0. A pull request's build is unchanged (no
versions). After merge: the Pages run on main, and on the next tag.
