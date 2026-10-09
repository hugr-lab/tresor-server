---
title: Observability
---

# Observability

The service says what it decided, and how it is doing. Nothing secret appears in any of it: no material,
token, variable value or delegation grant id.

## The audit

One JSON line on **stdout** per decision made for a caller. The service's own log goes to stderr.
Container Apps, AKS and Log Analytics collect stdout with no set-up.

```json
{"time":"2026-10-01T16:00:26Z","audit":"tresor-server/1","kind":"read","outcome":"ok",
 "principal":"subject:https://idp.example/realms/corp|8f1c…","actor":"client:acl-node","roles":["role:analysts"],
 "entry":"secret","name":"lake","version":3,
 "references":[{"param":"secret","ref":"ref+azkv://corp-vault/lake-s3","version":"0123…"}],
 "trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","span_id":"…","request_id":"00254879972471be"}
```

| kind | When |
| --- | --- |
| `read` | a secret's material or a variable's value served |
| `write`, `delete`, `annotate` | a PUT (`detail`: created / replaced), a DELETE, a PATCH |
| `grant`, `revoke` | a grant put or deleted; `target` is its principal |
| `delegation` | a delegation grant exchanged or revoked |
| `mint` | a token minted or refreshed for a caller (`token_exchange`); `target` is the audience |
| `inspect` | the console's view of what the service holds: an entry's shape, grants, the service, a references check (spec 010) |
| `reveal` | the console showed an administrator the parameters not marked secret (spec 010) |

- **`outcome`** is `ok`, `denied`, `invalid`, `precondition`, `refused` (the IdP's) or `error`. A refusal
  or an error also has a `reason`, in the protocol's terms (`no_verb`, `not_found`, `unauthenticated`, …).
- **`principal`** is the caller. **`actor`** is the server acting for the caller under a delegation grant.
  **`roles`** are the principals that decided: under a grant, the server's own.
- **A request that ended with no answer**, cancelled or failed inside, is `error`, with `reason: abandoned`.
- **An invisible name**: the caller gets the protocol's `404`, and the audit records the name with
  `denied`. Whoever reads the audit sees every name, and who used it.
- **`audit.level`**:
  - `all` (default): everything;
  - `changes`: everything but successful reads;
  - `off`: nothing.
- **To OpenTelemetry**: with an OTLP endpoint, each event is also a log record. Its body is the kind, its
  attributes `tresor.*`, and it carries the trace context.
- **The kinds line up with tresor's audit** (tresor spec 011). The `trace_id` joins the two.

## Traces

The service's spans **only continue tresor's trace**: it never starts one.

- tresor sends the `traceparent` of the statement it serves; on a duckdb-acl node, acl-otel exports that
  trace.
- When that `traceparent` is sampled, the service adds a span for the request, under tresor's, with children
  for:
  - the state store;
  - the KEK (Key Vault);
  - a reference's source;
  - the identity provider's token endpoint (`idp.token`).
- With no sampled `traceparent`, there are no spans.
- Spans are named by route (`GET /v1/secrets/{name}`), never by an entry's name.
- `telemetry.traces: false` turns them off. The audit keeps the `trace_id` either way.

## Metrics

| Metric | |
| --- | --- |
| `tresor.server.requests`, `tresor.server.duration` | by route and status class |
| `tresor.audit.events` | by kind and outcome; counted at every audit level |
| `tresor.audit.dropped` | events a writer failed to write |
| `tresor.kek.operations`, `tresor.kek.duration` | wrap, unwrap, root, by outcome |
| `tresor.references` | by scheme (the source's name: `vault`, or a named source's), kind and outcome |
| `tresor.mint` | by outcome |
| `tresor.state.conflicts` | compare-and-set writes lost and run again |
| `tresor.state.left_out` | rows or resources a list left out (their MAC; `kind` names the table or kind, `unchecked` a SQL row served with `state.mac` off) |
| `tresor.keys.data_keys` | data keys stored (counted every 10 minutes) |
| `tresor.keys.oldest_age` | the oldest data key's age, in seconds |
| `tresor.keys.rows_behind` | rows under another data key than the active one: `tresor-server reseal` moves them |

## Export

OpenTelemetry's standard variables. Nothing is exported unless an endpoint is set:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318   # http/protobuf
OTEL_SERVICE_NAME=tresor-server                          # the default
OTEL_RESOURCE_ATTRIBUTES=deployment.environment=prod
```

- **On Kubernetes**: set them through the chart's `env`, pointing to a collector in the cluster.
- **On Azure**: a collector exports to Azure Monitor (Log Analytics, Application Insights).
- The export is `http/protobuf` only: the service refuses `grpc`.
