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
	"github.com/hugr-lab/tresor-server/internal/mint"
	"github.com/hugr-lab/tresor-server/internal/telemetry"
)

// Spec 005: a request's span (under tresor's trace only), its metrics, and its audit event. The handlers fill
// what they decided into the request's observation; the event is emitted once the answer is known.

// WithExchangeAuth: how the service logs in at each issuer's token endpoint, by IssuerKey (spec 006); an
// issuer not in it uses its client secret.
func WithExchangeAuth(auth map[string]mint.ClientAuth) Option {
	return func(s *Server) { s.exchangeAuth = auth }
}

// WithAudit records the service's decisions (spec 005).
func WithAudit(a *audit.Auditor) Option { return func(s *Server) { s.audit = a } }

// observation is what one request did, filled as it is served.
type observation struct {
	pattern  string       // the route matched (authed); "" for one no audited route serves
	caller   *auth.Caller // once authenticated
	problem  string       // the problem document's type, if one was answered
	answered bool         // something was written: a handler that returned without an answer gave up
	event    audit.Event  // what the handlers say: the entry, its name, a target, a version, references
	kind     string       // a handler's own kind for its decision, over the route's (a reveal)
	// the trace an event belongs to: the caller's (a well-formed traceparent), the service's own span when one
	// is recorded under it, else the caller's span; none without a traceparent
	trace trace.SpanContext
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
	// the console's (spec 010)
	"GET /admin/v1/service":                 audit.KindInspect,
	"GET /admin/v1/secrets/{name}/shape":    audit.KindInspect,
	"GET /admin/v1/variables/{name}/shape":  audit.KindInspect,
	"PATCH /admin/v1/secrets/{name}/params": audit.KindWrite,
	"GET /admin/v1/grants":                  audit.KindInspect,
	"POST /admin/v1/refs-check":             audit.KindInspect,
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

// begin starts a request's observation and its span: a child of a sampled, well-formed traceparent, or none
// recorded (the sampler never samples a root). The traceparent alone is read, version 00 as the protocol says.
func (s *Server) begin(r *http.Request, w http.ResponseWriter) (*http.Request, *observation, trace.Span) {
	o := &observation{}
	o.event.RequestID = requestID()
	w.Header().Set("X-Request-Id", o.event.RequestID)
	ctx := r.Context()
	header := r.Header.Get("traceparent")
	if _, _, ok := traceIDs(header); ok {
		ctx = propagation.TraceContext{}.Extract(ctx, propagation.MapCarrier{"traceparent": header})
		o.trace = trace.SpanContextFromContext(ctx) // the caller's
	}
	ctx, span := telemetry.Tracer().Start(ctx, "HTTP "+r.Method, trace.WithSpanKind(trace.SpanKindServer))
	if span.IsRecording() {
		o.trace = span.SpanContext() // the service's own, under the caller's
	}
	ctx = context.WithValue(ctx, observationKey{}, o)
	return r.WithContext(ctx), o, span
}

// who is the event's principal, actor and the roles that decided: under a delegation grant the actor's own
// (specs/009), else the caller's.
func who(c *auth.Caller) (principal, actor string, roles []string) {
	if c == nil {
		return "", "", nil
	}
	ps := c.Principals
	if c.Actor != "" {
		ps = c.ActorPrincipals
	}
	for _, p := range ps {
		if !strings.HasPrefix(p, "subject:") {
			roles = append(roles, p)
		}
	}
	return c.Owner(), c.Actor, roles
}

// emit writes e with the request's trace: the ids on the event, the context on its OTLP record.
func (s *Server) emit(ctx context.Context, o *observation, e audit.Event) {
	if o.trace.IsValid() {
		e.TraceID, e.SpanID = o.trace.TraceID().String(), o.trace.SpanID().String()
	}
	// never the made-up ids of a span nobody records: the record carries the trace the event belongs to, or none
	s.audit.Emit(trace.ContextWithSpanContext(ctx, o.trace), e)
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
	if o.kind != "" {
		kind = o.kind
	}
	result := outcome(status)
	if !o.answered {
		result, o.problem = "error", "abandoned" // the request ended (or the handler panicked) with no answer
	}
	if span.IsRecording() {
		span.SetName(route)
		span.SetAttributes(attribute.String("http.route", route), attribute.Int("http.response.status_code", status))
		if o.event.Entry != "" {
			span.SetAttributes(attribute.String("tresor.entry", o.event.Entry))
		}
		if kind != "" {
			span.SetAttributes(attribute.String("tresor.outcome", result))
		}
		if status >= 500 || !o.answered {
			span.SetStatus(codes.Error, o.problem)
		}
	}
	span.End()
	if kind == "" {
		return
	}
	e := o.event
	e.Kind, e.Outcome = kind, result
	if e.Outcome != "ok" {
		e.Reason = o.problem
	}
	if o.caller != nil {
		e.Principal, e.Actor, e.Roles = who(o.caller)
	}
	s.emit(ctx, o, e)
}

func metricAttrs(kv ...attribute.KeyValue) metric.MeasurementOption {
	return metric.WithAttributes(kv...)
}

// auditMint records a token minted (or refreshed) for user, under actor when a server acts for them: the
// audience is the event's target; a refusal by the IdP is "refused", anything else that failed "error". Never
// the token.
func (s *Server) auditMint(ctx context.Context, user, actor *auth.Caller, audience, detail string, err error) {
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
	e.Principal, e.Actor, e.Roles = who(user)
	if actor != nil {
		e.Actor = actor.Client()
	}
	s.emit(ctx, o, e)
}
