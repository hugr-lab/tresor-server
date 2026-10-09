package telemetry

import (
	"context"
	"sync"
	"time"

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

// KeysSample is the data keys' state for the gauges (spec 019).
type KeysSample struct {
	Stored, RowsBehind int
	OldestAge          time.Duration
}

// ObserveKeys reports the data keys' state as gauges - tresor.keys.data_keys, tresor.keys.oldest_age,
// tresor.keys.rows_behind - read by read every `every` (a count of rows: not at each collection), until ctx ends.
// A read that fails reports nothing (no stale value) and calls failed.
func ObserveKeys(ctx context.Context, every time.Duration, read func(context.Context) (KeysSample, error), failed func(error)) error {
	var mu sync.Mutex
	var last *KeysSample
	refresh := func() {
		s, err := read(ctx)
		mu.Lock()
		last = nil
		if err == nil {
			last = &s
		}
		mu.Unlock()
		if err != nil && ctx.Err() == nil {
			failed(err)
		}
	}
	stored, err := meter.Int64ObservableGauge("tresor.keys.data_keys", metric.WithDescription("data keys stored"))
	if err != nil {
		return err
	}
	oldest, err := meter.Float64ObservableGauge("tresor.keys.oldest_age", metric.WithUnit("s"),
		metric.WithDescription("the oldest data key's age"))
	if err != nil {
		return err
	}
	behind, err := meter.Int64ObservableGauge("tresor.keys.rows_behind",
		metric.WithDescription("rows under another data key than the active one: tresor-server reseal moves them"))
	if err != nil {
		return err
	}
	if _, err := meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		mu.Lock()
		defer mu.Unlock()
		if last != nil {
			o.ObserveInt64(stored, int64(last.Stored))
			o.ObserveFloat64(oldest, last.OldestAge.Seconds())
			o.ObserveInt64(behind, int64(last.RowsBehind))
		}
		return nil
	}, stored, oldest, behind); err != nil {
		return err
	}
	go func() {
		refresh()
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				refresh()
			}
		}
	}()
	return nil
}
