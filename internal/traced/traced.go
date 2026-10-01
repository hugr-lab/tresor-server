// Package traced puts the service's spans and metrics around what it calls out to (spec 005): the state store,
// the KEK, a reference's source. Spans exist only under a caller's sampled trace (telemetry's sampler); the
// attributes say what was done, never a name's value, material or a key.
package traced

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/hugr-lab/tresor-server/internal/keys"
	"github.com/hugr-lab/tresor-server/internal/material"
	"github.com/hugr-lab/tresor-server/internal/state"
	"github.com/hugr-lab/tresor-server/internal/telemetry"
)

func span(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return telemetry.Tracer().Start(ctx, name, trace.WithSpanKind(trace.SpanKindInternal), trace.WithAttributes(attrs...))
}

func end(s trace.Span, err error) {
	if err != nil {
		s.SetStatus(codes.Error, "failed") // never the error's text: it may name what it read
	}
	s.End()
}

// Store traces a state.Store: its reads and writes, and the variables' namespace as itself.
func Store(st state.Store) state.Store { return &store{Store: st, entry: "secret"} }

type store struct {
	state.Store
	entry string
}

func (s *store) attr() attribute.KeyValue { return attribute.String("tresor.entry", s.entry) }

func (s *store) List(ctx context.Context) ([]*state.Secret, error) {
	ctx, sp := span(ctx, "state.list", s.attr())
	out, err := s.Store.List(ctx)
	end(sp, err)
	return out, err
}

func (s *store) Describe(ctx context.Context, name string) (*state.Secret, error) {
	ctx, sp := span(ctx, "state.describe", s.attr())
	out, err := s.Store.Describe(ctx, name)
	end(sp, ignoreNotFound(err))
	return out, err
}

func (s *store) Get(ctx context.Context, name string) (*state.Secret, error) {
	ctx, sp := span(ctx, "state.get", s.attr())
	out, err := s.Store.Get(ctx, name)
	end(sp, ignoreNotFound(err))
	return out, err
}

func (s *store) Update(ctx context.Context, name string, fn func(*state.Secret) (*state.Secret, error)) (*state.Secret, error) {
	ctx, sp := span(ctx, "state.update", s.attr())
	attempts := 0
	var refused error // fn's own answer (a precondition, a refusal): no failure of the store
	out, err := s.Store.Update(ctx, name, func(cur *state.Secret) (*state.Secret, error) {
		attempts++
		next, err := fn(cur)
		refused = err
		return next, err
	})
	sp.SetAttributes(attribute.Int("tresor.attempts", attempts))
	if err != nil && errors.Is(err, refused) {
		err = nil
	}
	end(sp, ignoreNotFound(err))
	return out, err
}

func (s *store) Variables() state.Store {
	return &store{Store: s.Store.Variables(), entry: "variable"}
}

func ignoreNotFound(err error) error {
	if errors.Is(err, state.ErrNotFound) {
		return nil
	}
	return err
}

// Wrapper traces and counts a KEK's operations.
func Wrapper(w keys.KeyWrapper) keys.KeyWrapper { return &wrapper{w} }

type wrapper struct{ keys.KeyWrapper }

func kek(ctx context.Context, op string, f func(context.Context) error) {
	start := time.Now()
	ctx, sp := span(ctx, "kek."+op)
	err := f(ctx)
	end(sp, err)
	attrs := metric.WithAttributes(attribute.String("operation", op), attribute.String("outcome", telemetry.Outcome(err)))
	telemetry.KEKOperations.Add(ctx, 1, attrs)
	telemetry.KEKDuration.Record(ctx, time.Since(start).Seconds(), attrs)
}

func (w *wrapper) Wrap(ctx context.Context, dek []byte) (wrapped []byte, kekID string, err error) {
	kek(ctx, "wrap", func(ctx context.Context) error { wrapped, kekID, err = w.KeyWrapper.Wrap(ctx, dek); return err })
	return
}

func (w *wrapper) Unwrap(ctx context.Context, wrapped []byte, kekID string) (dek []byte, err error) {
	kek(ctx, "unwrap", func(ctx context.Context) error { dek, err = w.KeyWrapper.Unwrap(ctx, wrapped, kekID); return err })
	return
}

func (w *wrapper) Root(ctx context.Context, kekID string) (root []byte, err error) {
	kek(ctx, "root", func(ctx context.Context) error { root, err = w.KeyWrapper.Root(ctx, kekID); return err })
	return
}

// Source traces and counts a reference source's reads.
func Source(src material.Source) material.Source { return &source{src} }

type source struct{ material.Source }

func (s *source) Resolve(ctx context.Context, ref material.Ref) (value, version string, err error) {
	ctx, sp := span(ctx, "material.resolve", attribute.String("tresor.scheme", s.Scheme()))
	value, version, err = s.Source.Resolve(ctx, ref)
	end(sp, err)
	telemetry.References.Add(ctx, 1, metric.WithAttributes(attribute.String("scheme", s.Scheme()),
		attribute.String("outcome", telemetry.Outcome(err))))
	return
}
