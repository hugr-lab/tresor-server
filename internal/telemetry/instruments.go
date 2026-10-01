package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// The service's instruments (spec 005). They are made from the global meter, which delegates to the provider
// Setup sets later, and do nothing without one. Attributes are low-cardinality and never secret: a route, a
// kind, an outcome - never a name.
var (
	meter = otel.Meter(Name)

	Requests, _       = meter.Int64Counter("tresor.server.requests", metric.WithDescription("requests, by route and status class"))
	Duration, _       = meter.Float64Histogram("tresor.server.duration", metric.WithUnit("s"), metric.WithDescription("request duration"))
	AuditEvents, _    = meter.Int64Counter("tresor.audit.events", metric.WithDescription("audit events, at every level"))
	AuditDropped, _   = meter.Int64Counter("tresor.audit.dropped", metric.WithDescription("audit events a writer failed to write"))
	KEKOperations, _  = meter.Int64Counter("tresor.kek.operations", metric.WithDescription("KEK operations"))
	KEKDuration, _    = meter.Float64Histogram("tresor.kek.duration", metric.WithUnit("s"), metric.WithDescription("KEK operation duration"))
	References, _     = meter.Int64Counter("tresor.references", metric.WithDescription("references resolved, by scheme and outcome"))
	Mints, _          = meter.Int64Counter("tresor.mint", metric.WithDescription("tokens minted for callers, by outcome"))
	StateConflicts, _ = meter.Int64Counter("tresor.state.conflicts", metric.WithDescription("compare-and-set writes lost and run again"))
	StateLeftOut, _   = meter.Int64Counter("tresor.state.left_out", metric.WithDescription("resources a list left out (their MAC)"))
)

// Tracer is the service's tracer: spans only under a caller's sampled trace (Setup's sampler).
func Tracer() trace.Tracer { return otel.Tracer(Name) }

// Add counts one on a counter with attributes.
func Add(ctx context.Context, c metric.Int64Counter, attrs ...attribute.KeyValue) {
	c.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// Outcome is "ok" or "error".
func Outcome(err error) string {
	if err != nil {
		return "error"
	}
	return "ok"
}
