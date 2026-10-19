# Spec 025: the docs on hugr-lab.com too (IONOS)

- **Status**: implemented (#74; asked by the hugr-lab.com session, accepted by the owner 2026-10-19)
- **Date**: 2026-10-19
- **Author**: hugr lab

## Summary

The docs stay on GitHub Pages (https://hugr-lab.github.io/tresor-server/) and are built a second time for
https://hugr-lab.com/docs/tresor-server/ (IONOS, Apache), uploaded by SFTP. Both carry legal links (Impressum,
Datenschutz), each its site's.

## Design

- `website/docusaurus.config.ts`: `DOCS_TARGET=ionos` switches `url`, `baseUrl`, the main site's link and the legal
  links to hugr-lab.com; the default stays GitHub Pages. A footer column *Legal* on every page. Links to tresor
  and inside the texts stay on hugr-lab.github.io for now.
- **No request to another host** in the IONOS copy (hugr-lab.com's CSP for /docs/, and its privacy notice):
  no badge, font, CDN, external image or fetch - links only. docs-build.yml builds the copy on every pull request
  and fails on any `src`, `srcset`, `url(` or `@import` of an absolute http(s) URL.
- **pages.yml**: after the Pages build, the IONOS build and its upload (`lftp mirror --reverse --delete` into
  `${IONOS_DOCS_ROOT:-/hugr-lab/docs}/tresor-server` only) - both only when the organisation's variable
  `DOCS_IONOS` is `true`; on pushes to main and dispatch, never on a pull request. The SFTP credentials are the
  organisation's secrets (`IONOS_SFTP_HOST`, `_USER`, `_PASSWORD`): this repository creates none.

## Enforcement & security

The upload touches the product's folder only. Until `DOCS_IONOS` is set, nothing is built for IONOS nor sent.
