# Spec 005: observability - the audit, traces and metrics

- **Status**: accepted
- **Date**: 2026-10-01
- **Author**: hugr lab

## Summary

The service says what it did and how it is doing, in three ways:
- **an audit**: who read, wrote, granted or was refused what. It goes to stdout as JSON lines, and to
  OpenTelemetry logs when an OTLP endpoint is set;
- **traces**: only as a continuation of tresor's trace. tresor (spec 011, through acl-otel) traces the client's
  side, in the trace of the statement that caused it, and sends its `traceparent`. The service adds its own
  spans under it: the store, the KEK, a reference's source, the identity provider;
- **metrics**: requests, latencies, refusals, the KEK, references, minted tokens, resources a list left out.

Nothing secret in any of them: no material, token, data key, delegation id or variable value.

## Problem

- Today the service writes a request log line (method, path, status, subject) and its own errors. Nothing
  says which secret a caller read, who changed a grant, or what was refused.
- tresor (spec 011) audits and traces the client's side, through acl-otel, and sends the statement's
  `traceparent`. The service logs the trace id but makes no spans: in that trace, the service's time (the
  KEK, Key Vault, the IdP) is one opaque call.
- An operator has no numbers: how many fetches, how many refusals, how slow the KEK is, how often a
  reference fails.
- Spec 001 promised an audit to OpenTelemetry (on Azure, to Log Analytics through a collector).

## Design

### The decisions (the owner's, 2026-10-01)

- **The audit goes to stdout, and to OTLP when it is configured.** On stdout a platform collects it with no
  setup (Container Apps, AKS, Log Analytics); OTLP is for a collector.
- **Traces continue tresor's; the service starts none.** tresor is the client, and acl decides what is
  traced. With no sampled `traceparent`, the service makes no spans; the audit and the metrics stay.
- **Everything is audited, reads included**, by default; a **level** leaves reads out:

  | `audit.level` | What |
  | --- | --- |
  | `all` (default) | everything below |
  | `changes` | writes, deletes, annotations, grants, delegation, and every refusal; no successful read |
  | `off` | nothing (the request log and the traces stay) |

### The audit

One event per decision the service made for a caller. The kinds follow tresor's (spec 011), so the two sides
line up:

| kind | When | Outcome |
| --- | --- | --- |
| `read` | a secret's material or a variable's value served (`GET /v1/{secrets,variables}/{name}`) | `ok`, `denied`, `error` |
| `write` | a PUT: created or replaced | `ok` (`created` / `replaced` in `detail`), `denied`, `precondition`, `invalid`, `error` |
| `delete` | a DELETE | `ok`, `denied`, `error` |
| `annotate` | a PATCH | as above |
| `grant`, `revoke` | a grant put or deleted; `target` is its principal | as above |
| `delegation` | a grant exchanged, revoked, or revoked by actor or user | `ok`, `denied`, `error`; `detail`: `exchanged` / `revoked` |
| `mint` | a token minted or refreshed for a caller (`token_exchange`) | `ok`, `refused` (the IdP's), `error` |

- **Who:**
  - `principal`: the caller as the protocol spells it (`subject:<issuer>|<sub>`), or `client:<id>` for a
    service;
  - `actor`: the server acting under a delegation grant, when one does; never the grant's id;
  - `roles`: the caller's roles and groups that decided it.
- **What:**
  - `entry`: `secret` or `variable`;
  - `name`: the entry's name;
  - `target`: a grant's principal, for `grant` and `revoke`;
  - `version`: the version written or read.
- **Why:** `outcome`, and `reason` for a refusal or an error, in the protocol's terms (`no_verb`,
  `not_found`, `actor_not_allowed`, `service_error`, ...).
- **References** resolved for a read are in its event: each parameter's reference (where, never the value)
  and the version read.
- **Correlation:** the request's `trace_id` and `span_id` (the service's own span), and the `request_id`.
- **A refusal to an invisible name** (`404` for an entry that exists but the caller may not see) is
  recorded as `denied`, `reason: not_found`. The record holds the name: the audit's reader may see what the
  caller may not.
- **Never:** material, a token, a variable's value, a delegation grant's id, a header.

On stdout, one JSON object per line: `{"time":…,"audit":"tresor-server/1","kind":"read",…}`. The
`audit` key tells the audit apart from the service's log, which goes to stderr.

To OTLP, each event is an OpenTelemetry log record:
- its body is the kind;
- its attributes are the fields above, under `tresor.*`;
- it carries the trace context of the request's span.

### Traces

- **Only under a caller's trace.** The sampler is parent-based and never samples a root.
  - A well-formed `traceparent` whose sampled flag is set gives the request a server span, a child of
    tresor's HTTP span.
  - Anything else gives no span: no `traceparent`, an unsampled one, or a malformed one.
  - The audit's `trace_id` comes from the `traceparent` either way, so tresor's events (acl-otel) and the
    service's join on it, even with the spans off.
- **A server span per request**, named by its route (`GET /v1/secrets/{name}`, never the path with the
  name). Its attributes: `http.route`, the status, `tresor.entry`, `tresor.outcome`. Never the name in the
  span name.
- **Child spans** where the time goes:
  - the store (`state.get`, `state.update` with its attempts, `state.list`);
  - the KEK (`kek.wrap`, `kek.unwrap`, `kek.root`);
  - a reference (`material.resolve`, with the scheme);
  - the identity provider (`idp.jwks`, `idp.exchange`).
- A malformed `traceparent` is ignored (the protocol). `tracestate` and `baggage` are not read.

### Metrics

| Instrument | Attributes |
| --- | --- |
| `tresor.server.requests` (counter), `tresor.server.duration` (histogram, s) | route, status class |
| `tresor.audit.events` (counter) | kind, outcome - counted at every level, `off` included |
| `tresor.kek.operations` (counter), `tresor.kek.duration` (histogram) | operation, outcome |
| `tresor.references` (counter) | scheme, outcome |
| `tresor.mint` (counter) | outcome |
| `tresor.state.conflicts` (counter) | operation: a compare-and-set lost and run again |
| `tresor.state.left_out` (counter) | kind: a Kubernetes resource a list left out (its MAC) |

### Configuration

```yaml
audit:
  level: all        # all | changes | off
telemetry:
  traces: true      # spans under tresor's trace; false: the audit's trace_id only
```

OpenTelemetry takes its standard environment variables. Nothing is exported unless an endpoint is set:
- `OTEL_EXPORTER_OTLP_ENDPOINT` or a per-signal endpoint;
- `OTEL_EXPORTER_OTLP_PROTOCOL` (`http/protobuf` by default, or `grpc`);
- `OTEL_SERVICE_NAME` (default `tresor-server`), `OTEL_RESOURCE_ATTRIBUTES`;
- `OTEL_SDK_DISABLED=true` turns all of it off.

The chart passes them through `env`; the Container Apps recipe documents a collector.

### Packages

- `internal/audit`: the events, their writers (stdout JSON, OTLP log), the level.
- `internal/telemetry`: the SDK's set-up from the environment, the tracer and the meter, shut down
  (flushed) at the service's end.
- Spans and metrics are added in place: the API's handlers, the stores' `Update`, the envelope, the
  material sources, the mint client.

## Enforcement & security

- **Nothing secret.** The audit's fields are a closed set; values are never passed to it. Tests look for
  the material and the tokens of a whole run in the audit, the spans and the metrics, and find none.
- **The audit never decides.** A writer that fails (a full stdout, an OTLP outage) never fails a request.
  The event is dropped and counted (`tresor.audit.dropped`). OTLP batches in the background.
- **The `traceparent` is correlation only** (the protocol): never a reason to allow or refuse.
- **Names are in the audit.** It is as sensitive as the store's list of names: whoever reads the audit
  sees every entry's name, and who used it.

## Testing

- **The audit.**
  - For each kind and outcome, the API's tests read the stdout writer's lines and check them.
  - The levels: `changes` drops successful reads only, and `off` writes nothing.
  - A run's material, tokens, values and delegation ids are nowhere in the audit.
- **Traces.** An in-memory exporter checks:
  - the parent a `traceparent` gives;
  - no span without a sampled `traceparent`;
  - the span names (routes, never names);
  - the children for the store, the KEK and a reference.
- **Metrics.** An in-memory reader checks the counters for a run.
- **On kind**: the chart with an OpenTelemetry collector in the cluster. The audit and the spans arrive, and
  a secret's material is not in them.

## Alternatives considered

- **The audit only to OTLP.** Without a collector there would be no audit. stdout is always there.
- **The audit in the state store.** Every read would become a write. An audit belongs to a log pipeline,
  not to the store of secrets.
- **Reads as metrics only.** Refused: who read what is the audit's main question. The level `changes`
  exists for those who choose otherwise.
- **The Azure Monitor exporter.** OTLP to a collector covers Azure and every other cloud.
- **Root spans for every request.** Refused: tresor is the client and its trace is the one an operator
  follows. Requests made outside it (curl, scripts) are in the audit and the metrics.
- **No spans at all, the trace id only.** That loses where the time goes inside the service (the KEK,
  Key Vault, the IdP), which is what "this statement is slow" asks.
