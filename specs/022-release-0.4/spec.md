# Spec 022: release 0.4.0 - tresor's browsers, the MAC on by default, signed artifacts

- **Status**: draft
- **Date**: 2026-10-14
- **Author**: hugr lab

## Summary

0.4.0 (the owner, 2026-10-14) brings tresor-server to tresor's current protocol, turns the SQL stores' MAC on by
default, and signs what it ships:

1. **tresor's main**: the conformance pin moves from `f906621` to tresor's main; the one protocol change since is
   tresor spec 020's *Browsers* note - CORS for web pages (DuckDB-wasm) on every route, discovery included.
2. **`state.mac: true` by default** on the SQL stores (spec 014 left it for a version that may change defaults).
3. **Signed artifacts**: the image and the chart signed keylessly (cosign, GitHub's OIDC), the image with an SBOM
   and provenance attestations, and scanned for vulnerabilities in CI.
4. **The release's documents**: `SECURITY.md`, a support matrix, the upgrade from 0.3.

## Problem

- **Browsers**: tresor in a web page calls the service cross-origin. Today CORS covers `/v1/`, `/admin/v1/` and
  `/ui/mfe/` for the console's microfrontend hosts (`ui.allowed_origins`, spec 010) - not discovery
  (`/.well-known/duckdb-secrets`), and its preflight allows neither `Accept` nor `Delegation`. A page with DuckDB-wasm
  cannot even discover the service.
- **The MAC off by default**: every write carries a MAC since 0.2.0 (spec 014), but reads check it only with
  `state.mac: true` - a database writer can still add a grant on a default install.
- **Unsigned artifacts**: nothing proves an image or a chart came from this repository's workflows; no SBOM; no scan
  of the image (govulncheck covers Go, not the base image).
- **No security policy, no support matrix**: where to report a vulnerability; which Kubernetes, PostgreSQL, SQL Server
  versions are checked.

## Design

### 1. CORS for browsers (tresor's protocol, *Browsers*)

- A setting of the protocol's own: `cors.allowed_origins` - the origins of web pages that call the service (tresor in
  DuckDB-wasm). For those: CORS on **every route discovery includes** - `/.well-known/duckdb-secrets`, `/v1/...`.
- `ui.allowed_origins` (the console's hosts, spec 010) keeps `/ui/mfe/`, `/admin/v1/` and `/v1/`; it implies nothing
  for the protocol's pages, nor they for the console.
- The preflight allows the protocol's methods and the headers `Authorization`, `Content-Type`, `Accept`,
  `Delegation`, `If-Match`, `If-None-Match`, `traceparent`; answers expose `ETag` (and `X-Request-Id`); no
  `Access-Control-Allow-Credentials` - no cookie is sent or honoured; `Vary: Origin` always.
- An origin is `https://host[:port]` (http on loopback only), no path, no wildcard - refused at start otherwise, as
  `ui.allowed_origins` is.
- Docs: the Configuration page (`cors`), a short *Web pages (DuckDB-wasm)* section on the References or Getting
  started page.

### 2. `state.mac: true` by default

- The SQL stores' default becomes `true`; `state.mac: false` turns the checks off (logged at start, as a warning).
- **An upgrade from a database with rows written before 0.2.0** (no MAC): at start, with the checks on, the store
  counts the rows with no MAC; any - the start stops with what to do: run `tresor-server mac` (spec 014), or set
  `state.mac: false` for now. Never a silent `ErrSealed` on reads.
- Kubernetes and memory unchanged (the Kubernetes store always MACs; memory has nothing at rest).

### 3. Signed artifacts

- **The image** (`image.yml`): `docker/build-push-action` with `provenance: mode=max` and `sbom: true` (BuildKit's
  attestations, in the registry beside the image); then `cosign sign` of the pushed digest, keyless (the workflow's
  OIDC token, Fulcio, Rekor) - no key anywhere.
- **The chart** (`chart.yml`): after `helm push`, `cosign sign` of the chart's OCI digest the same way.
- **Scan**: Trivy on the image in CI (a PR builds it without pushing) - a finding of severity HIGH or CRITICAL with a
  fix available fails the job; unfixed ones are reported, not failing. Pinned action versions.
- **Docs**: a *Verifying* section - `cosign verify ghcr.io/hugr-lab/tresor-server:<v>
  --certificate-identity-regexp '^https://github.com/hugr-lab/tresor-server/\.github/workflows/' 
  --certificate-oidc-issuer https://token.actions.githubusercontent.com`, the same for the chart; the SBOM and
  provenance through `docker buildx imagetools inspect`.

### 4. The release's documents

- `SECURITY.md`: how to report (GitHub's private vulnerability reporting), what is in scope, the supported versions
  (the latest minor).
- A **support matrix** (Operations, or its own page): what CI and the live runs check - Kubernetes (kind's version,
  AKS, GKE, EKS), PostgreSQL, SQL Server, SQLite, the clouds' KMS and secret stores, the tresor version.
- **Upgrading to 0.4** (Administration → Upgrading): `state.mac` on by default (and the start's refusal), `cors`
  new, nothing else to do.
- Spec 001 (the architecture) to implemented: every phase it named is done.

### The order

One PR per part: (1) the pin and CORS - tresor's conformance on every store with the new pin; (2) the MAC default;
(3) signing, SBOM, scan; (4) the documents; then the tag `v0.4.0` and its release notes.

## Enforcement & security

- CORS: an origin list, never `*`; no credentials; the token stays the only credential; discovery's answer is
  public anyway, but now readable by the listed pages only.
- The MAC on by default: who can write the database cannot add a grant, change a scope or a delegation unseen.
- Signatures: keyless, bound to this repository's workflow identity; a verifier checks the identity, not a key.

## Testing

- CORS: the API's tests - a listed origin on discovery and `/v1` (preflight and request), an unlisted one (no
  headers), `ui.allowed_origins` and `cors.allowed_origins` apart, the config's refusals; tresor's conformance at its
  main on every store.
- The MAC default: the state suite as now; an upgrade test - a database with a MAC-less row, the start refused with
  the message, `tresor-server mac`, then the start passes.
- Signing: the release workflows verify their own signature (`cosign verify`) after signing; the scan runs on PRs.

## Alternatives considered

- **One CORS list for the console and the protocol**: a console host would become a protocol page and the reverse;
  two lists keep each the owner's choice.
- **The MAC on by default only for new databases** (no MAC-less rows): the same in effect - an old database with
  MAC-less rows is the one case, and refusing to start with what to do is clearer than a quiet exception.
- **A long-lived signing key**: a secret to keep and rotate; keyless signing ties a signature to the workflow.

## Follow-ups

- Artifact Hub listing for the chart.
- 1.0: the compatibility policy (what 1.x promises: the protocol, the configuration, the chart's values, the
  console's contract v1, forward-only migrations).
