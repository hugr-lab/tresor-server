# Spec 028: the chart's config through tpl

- **Status**: implemented (#80; the owner, 2026-10-21; asked by the duckdb-acl session for the umbrella chart `hugr`)
- **Date**: 2026-10-21
- **Author**: hugr lab

## Summary

An umbrella chart holds an install's facts once, as `global` values (a database host, an issuer, a namespace); a
parent cannot compute its subcharts' values. With `configTemplate: true` the chart renders `config` through `tpl`
with its own context first, so `state.dsn`, the issuers or `policy.admins` take them.

## Design

- One helper, `tresor.cfg`, is `config` - through `tpl` with `configTemplate`, as it is otherwise - and every use
  of `config` in the chart (the service's file, the RBAC derived from `material.k8s.allow` and
  `state.password_ref`, the checks) reads it: they see the same rendered values.
- Off by default: without it the render is the same, byte for byte. With it a literal `{{` in `config` is written
  `{{ "{{" }}`. The service's own syntax (`${…}`, `mint+…`) is in its secrets, never in `config`.

## Testing

A render compared byte for byte without the flag; chart.yml renders one with a `global` value in `state.dsn`.
