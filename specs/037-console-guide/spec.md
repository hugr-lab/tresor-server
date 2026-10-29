# Spec 037: the console in the docs, with screenshots

- **Status**: accepted (the owner, 2026-10-29: "подтверждаю" - the tasks after the public release)
- **Date**: 2026-10-29
- **Author**: hugr lab

## Summary

A page that walks through the console - what an administrator sees and does - with screenshots of the console
as 0.8.2 ships it (the tresor mark, the 0.7.5 contrast fix, the 0.8.0 service view, #105's fixes).

## Design

- `website/docs/console-guide.md` ("Using the console", after Console in the sidebar; Console links it): signing in
  and the non-administrator page; the secrets list; a secret's parameters (values hidden, a reference shown with its
  source, Show values audited, SQL); creating a secret (a type's template, a reference with the source's allowlist,
  the statement live; replace keeps what is untouched); granting and revoking by role and group; Access by
  principal; the references check (with a finding); variables (plain, made per caller); the service view; the
  account menu, revoking sessions, signing out, the session's end while editing.
- Screenshots in `website/static/img/console/` (PNG, 1600 px wide; the sign-in pages 1280), taken with Playwright on
  the Docker demo (spec 033) with an OpenBao beside the service for `ref+vault` (a dev server, a KV secret, the
  `vault` source) and sample entries: a referenced secret, one with a claim in a header, a variable made per caller.
  Nothing shown is a real secret; the stand's passwords are not in any shot.

## Findings (the console; fixed in #105, the screenshots taken with it)

- At 1280 px the editor's parameters table is too narrow beside the SQL preview: a reference's fields shrink to a
  few letters and the table is cut at the right.
- A variable made per caller (`mint+claim://…`) is labelled "sensitive · reference" and "its value is a reference".
- A secret made per caller from a claim is labelled "dynamic · token per caller".

## Testing

The docs build (links and images resolve; the hugr-lab.com copy requests no other server).
