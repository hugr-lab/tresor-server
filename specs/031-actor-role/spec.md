# Spec 031: a delegation actor by role

- **Status**: implemented (#90; the owner, 2026-10-22: "да давай"; asked by duckdb-acl)
- **Date**: 2026-10-22
- **Author**: hugr lab

## Summary

`policy.actors` names a service by its client id only, so a platform with a node group per client lists every
group's client, and each new group needs the service's config changed. An actor may now be a role: every
service whose token carries it acts for users with the rule's verbs.

## Design

- **Config**: `principal: role:<name>` besides `client:<id>`; a role's `issuer` is required and must be one of
  `issuers` (another issuer's same-named role does not pass for it). Verbs as for a client. Config only - no
  runtime API.
- **Policy**: a rule naming the client wins; else a role rule matches when the token is a service's (it has a
  `client:` principal), comes from the rule's issuer and carries the role. The same check at the exchange, at
  minting under a grant, and for the verbs and `create` under a grant (the actor's principals are kept with the
  grant already). A grant in use is presented by a service token of its own client, so the role is checked again
  at every use: taken from the node, its grants stop working.
- The console's service view shows an actor's issuer.
- **Risk** (in the docs): a role is broader than a client id - whoever can give it in the identity provider lets
  a client act for every user.
- No protocol change: actors are this service's policy.

## Testing

Policy: the role from its issuer only, a service only, not a group of the same name, a client rule first, no
`create` through a `use` rule. Config: a role without an issuer or with an unknown one refused. API: two node
groups by one role exchange and use a secret granted to the role; a person with the role is refused.
