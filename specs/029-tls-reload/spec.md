# Spec 029: the TLS certificate read again when it changes

- **Status**: accepted (the owner, 2026-10-21; asked by the duckdb-acl session for the umbrella chart's cert-manager)
- **Date**: 2026-10-21
- **Author**: hugr lab

## Summary

The service read `tls.cert` and `tls.key` once, at start. cert-manager renews a certificate in place (a 90-day
certificate, renewed at day 60): a replica that had not restarted would serve an expired one. Now the pair is read
again when its files change, and served without a restart.

## Design

- `internal/tlsreload`: the server's `tls.Config.GetCertificate` gives the pair in service. Every 30 s the files
  are read; a pair whose contents changed (a Secret's files are swapped through its `..data` symlink) is checked
  whole - `tls.X509KeyPair` (the key the certificate's) and the certificate in date - and only then serves.
- A bad new pair (no file, a mismatch, out of date) leaves the old one serving: an error in the log, and readiness's
  `tls` check degraded (soft: a restart would not help). A start with a pair that does not load fails.
- Nothing of the key is logged: the subject and the expiry of a pair taken.
- The chart is unchanged: it mounts the TLS Secret as a directory.

## Testing

Go: real TLS handshakes - a pair renewed through the symlink swap served, a mismatched and an expired pair refused
with the old one serving and readiness degraded, a good one again ready.
