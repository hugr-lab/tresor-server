# Spec 026: an unattended install - the cluster's own accounts, a namespace of its own

- **Status**: accepted (the owner, 2026-10-20; asked by the duckdb-acl session for hugr-platform spec 005)
- **Date**: 2026-10-20
- **Author**: hugr lab

## Summary

An umbrella chart (`hugr`: hugr-platform, tresor-server, kista) installs itself: an install Job, `hugr-init`, writes
the policy catalog's login into tresor and grants it, under a ServiceAccount of its own. Two things were missing:
the chart's objects in a namespace of their own (`namespaceOverride`), and trusting the cluster's own
ServiceAccount issuer - whose discovery a Kubernetes API server serves to authenticated accounts only, under the
cluster's CA. The Job is a full administrator (the owner: no narrower role).

## Design

- **Chart**: `namespaceOverride` - every namespaced object's `metadata.namespace`, every reference to the
  namespace (RBAC subjects, the admission policy, NOTES); default: the release's. `clusterIssuer.enabled` mounts the
  service's projected token (the API server's audience) and the cluster's CA (`kube-root-ca.crt`) at
  `/var/run/tresor/cluster/{token,ca.crt}`.
- **Issuer**: `ca_file` (PEM, added to the system's roots for the issuer's discovery and keys) and
  `discovery_token_file` (a bearer token read at each request, sent to the issuer's host and, once discovered,
  its keys' host only; https only).
- **The account as admin**: by the existing service rule, `service: {claim: kubernetes.io, client_claim: sub}` -
  `client:system:serviceaccount:<ns>:<name>` - or by `subject:<issuer>|system:serviceaccount:<ns>:<name>`.

## Enforcement & security

The token goes to the issuer's own hosts only, never on a redirect elsewhere; it is never logged. The issuer is
trusted for the accounts it names: list one account as admin, in a namespace no one else creates pods in.

## Testing

Go: a TLS issuer serving its discovery and keys with a token only (refused without it, or without the CA). kind
(CI): the release in one namespace, its objects in another; the cluster's issuer; an install Job writes and grants
a secret as an administrator by its projected token.
