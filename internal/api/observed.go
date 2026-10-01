package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/hugr-lab/tresor-server/internal/audit"
	"github.com/hugr-lab/tresor-server/internal/auth"
	"github.com/hugr-lab/tresor-server/internal/telemetry"
)

// Spec 005: a request's span (under tresor's trace only), its metrics, and its audit event. The handlers fill
// what they decided into the request's observation; the event is emitted once the answer is known.

// WithAudit records the service's decisions (spec 005).
func WithAudit(a *audit.Auditor) Option { return func(s *Server) { s.audit = a } }

// observation is what one request did, filled as it is served.
type observation struct {
	pattern string       // the route matched (authed); "" for one no audited route serves
	caller  *auth.Caller // once authenticated
	problem string       // the problem document's type, if one was answered
	event   audit.Event  // what the handlers say: the entry, its name, a target, a version, references
}

type observationKey struct{}

func observed(r *http.Request) *observation { return observedIn(r.Context()) }

func observedIn(ctx context.Context) *observation {
	o, _ := ctx.Value(observationKey{}).(*observation)
	if o == nil {
		return &observation{} // outside the middleware (tests of a handler alone): written to nowhere
	}
	return o
}

// auditKinds maps a route to what its decision is, for the audit; routes not here (lists, whoami, the
// discovery, a grants list) are not audited.
var auditKinds = map[string]string{
	"GET /v1/secrets/{name}":                  audit.KindRead,
	"GET /v1/variables/{name}":                audit.KindRead,
	"PUT /v1/secrets/{name}":                  audit.KindWrite,
	"PUT /v1/variables/{name}":                audit.KindWrite,
	"DELETE /v1/secrets/{name}":               audit.KindDelete,
	"DELETE /v1/variables/{name}":             audit.KindDelete,
	"PATCH /v1/secrets/{name}":                audit.KindAnnotate,
	"PATCH /v1/variables/{name}":              audit.KindAnnotate,
	"PUT /v1/secrets/{name}/grants/{id}":      audit.KindGrant,
	"PUT /v1/variables/{name}/grants/{id}":    audit.KindGrant,
	"DELETE /v1/secrets/{name}/grants/{id}":   audit.KindRevoke,
	"DELETE /v1/variables/{name}/grants/{id}": audit.KindRevoke,
	"POST /v1/delegations":                    audit.KindDelegation,
	"DELETE /v1/delegations/{id}":             audit.KindDelegation,
	"DELETE /v1/delegations":                  audit.KindDelegation,
}

// outcome reads an answer's status as the audit says it.
func outcome(status int) string {
	switch {
	case status < 300:
		return "ok"
	case status == http.StatusUnauthorized, status == http.StatusForbidden, status == http.StatusNotFound:
		return "denied"
	case status == http.StatusPreconditionFailed:
		return "precondition"
	case status == http.StatusUnprocessableEntity, status == http.StatusBadRequest:
		return "invalid"
	}
	return "error"
}

func requestID() string {
	raw := make([]byte, 8)
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)
}

// begin starts a request's observation and its span: a child of a sampled traceparent, or none recorded (the
// sampler never samples a root).
func (s *Server) begin(r *http.Request, w http.ResponseWriter) (*http.Request, *observation, trace.Span) {
	o := &observation{}
	o.event.RequestID = requestID()
	w.Header().Set("X-Request-Id", o.event.RequestID)
	// the W3C trace context only: the protocol defines traceparent and nothing else (tracestate, baggage)
	carrier := propagation.MapCarrier{"traceparent": r.Header.Get("traceparent")}
	ctx := propagation.TraceContext{}.Extract(r.Context(), carrier)
	ctx, span := telemetry.Tracer().Start(ctx, "HTTP "+r.Method, trace.WithSpanKind(trace.SpanKindServer))
	ctx = context.WithValue(ctx, observationKey{}, o)
	return r.WithContext(ctx), o, span
}

// finish ends the span, counts the request, and emits the audit event of an audited route.
func (s *Server) finish(r *http.Request, o *observation, span trace.Span, status int, took time.Duration) {
	ctx := r.Context()
	route := o.pattern
	if route == "" {
		route = "unmatched"
	}
	class := strconv.Itoa(status/100) + "xx"
	telemetry.Requests.Add(ctx, 1, metricAttrs(attribute.String("route", route), attribute.String("status_class", class)))
	telemetry.Duration.Record(ctx, took.Seconds(), metricAttrs(attribute.String("route", route)))
	kind := auditKinds[o.pattern]
	if span.IsRecording() {
		span.SetName(route)
		span.SetAttributes(attribute.String("http.route", route), attribute.Int("http.response.status_code", status))
		if o.event.Entry != "" {
			span.SetAttributes(attribute.String("tresor.entry", o.event.Entry))
		}
		if kind != "" {
			span.SetAttributes(attribute.String("tresor.outcome", outcome(status)))
		}
		if status >= 500 {
			span.SetStatus(codes.Error, o.problem)
		}
	}
	span.End()
	if kind == "" {
		return
	}
	e := o.event
	e.Kind, e.Outcome = kind, outcome(status)
	if e.Outcome != "ok" {
		e.Reason = o.problem
	}
	if c := o.caller; c != nil {
		e.Principal, e.Actor = c.Owner(), c.Actor
		for _, p := range c.Principals {
			if !strings.HasPrefix(p, "subject:") {
				e.Roles = append(e.Roles, p)
			}
		}
	}
	// the caller's trace (correlation only): its id, and the span the event belongs to - the service's own when
	// it records one, else the caller's
	if traceID, spanID, ok := traceIDs(r.Header.Get("traceparent")); ok {
		e.TraceID, e.SpanID = traceID, spanID
		if sc := span.SpanContext(); span.IsRecording() && sc.IsValid() {
			e.SpanID = sc.SpanID().String()
		}
	}
	s.audit.Emit(trace.ContextWithSpanContext(ctx, span.SpanContext()), e)
}

func metricAttrs(kv ...attribute.KeyValue) metric.MeasurementOption {
	return metric.WithAttributes(kv...)
}

// auditMint records a token minted (or refreshed) for the request's caller at its IdP: the audience is the
// event's target; a refusal by the IdP is "refused", anything else that failed "error". Never the token.
func (s *Server) auditMint(ctx context.Context, audience, detail string, err error) {
	o := observedIn(ctx)
	e := audit.Event{Kind: audit.KindMint, Outcome: "ok", Detail: detail, Target: audience, Entry: o.event.Entry,
		Name: o.event.Name, RequestID: o.event.RequestID}
	switch {
	case err != nil && isRefusal(err):
		e.Outcome = "refused"
	case err != nil:
		e.Outcome = "error"
	}
	telemetry.Add(ctx, telemetry.Mints, attribute.String("outcome", e.Outcome))
	if c := o.caller; c != nil {
		e.Principal, e.Actor = c.Owner(), c.Actor
	}
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		e.TraceID, e.SpanID = sc.TraceID().String(), sc.SpanID().String()
	}
	s.audit.Emit(ctx, e)
}
