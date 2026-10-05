// Package audit records what the service decided for its callers (spec 005): who read, wrote, granted or was
// refused what. One event per decision, to stdout as a JSON line, and to OpenTelemetry logs when an OTLP
// endpoint is set. The fields are a closed set: material, a token, a variable's value or a delegation grant's
// id is never one of them. A writer that fails never fails a request.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"

	"github.com/hugr-lab/tresor-server/internal/telemetry"
)

// Format names the events' shape: the "audit" key of every line.
const Format = "tresor-server/1"

// Level is how much is recorded.
type Level int

const (
	All     Level = iota // everything, reads included
	Changes              // writes, deletes, annotations, grants, delegation, reveals, every refusal; no successful read or inspection
	Off                  // nothing (the events are still counted)
)

// ParseLevel reads audit.level: all (the default), changes or off.
func ParseLevel(s string) (Level, error) {
	switch s {
	case "", "all":
		return All, nil
	case "changes":
		return Changes, nil
	case "off":
		return Off, nil
	}
	return All, fmt.Errorf("audit.level is all, changes or off")
}

// The kinds (tresor spec 011's, where they meet).
const (
	KindRead       = "read"
	KindWrite      = "write"
	KindDelete     = "delete"
	KindAnnotate   = "annotate"
	KindGrant      = "grant"
	KindRevoke     = "revoke"
	KindDelegation = "delegation"
	KindMint       = "mint"
	// KindInspect: an administrator looked at what the service holds, never a value (spec 010's console)
	KindInspect = "inspect"
	// KindReveal: an administrator asked for the values of parameters not marked secret (spec 010)
	KindReveal = "reveal"
)

// Ref is a reference resolved for a read: where, and the version read - never the value.
type Ref struct {
	Param   string `json:"param"`
	Ref     string `json:"ref"`
	Version string `json:"version,omitempty"`
}

// Event is one decision.
type Event struct {
	Time      time.Time `json:"time"`
	Audit     string    `json:"audit"`
	Kind      string    `json:"kind"`
	Outcome   string    `json:"outcome"`          // ok, denied, invalid, precondition, refused, error
	Reason    string    `json:"reason,omitempty"` // the protocol's problem type, for a refusal or an error
	Detail    string    `json:"detail,omitempty"` // created, replaced, exchanged, revoked, minted, refreshed
	Principal string    `json:"principal,omitempty"`
	Actor     string    `json:"actor,omitempty"` // the server acting under a delegation grant
	Roles     []string  `json:"roles,omitempty"`
	Entry     string    `json:"entry,omitempty"` // secret, variable
	Name      string    `json:"name,omitempty"`
	Target    string    `json:"target,omitempty"` // a grant's principal
	Version   int64     `json:"version,omitempty"`
	Refs      []Ref     `json:"references,omitempty"`
	TraceID   string    `json:"trace_id,omitempty"`
	SpanID    string    `json:"span_id,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
}

// Auditor writes events at its level. Safe for concurrent use.
type Auditor struct {
	level  Level
	mu     sync.Mutex
	out    io.Writer
	logger otellog.Logger
	now    func() time.Time
}

// New returns an auditor writing JSON lines to out (stdout), and log records to the global logger provider
// (OTLP, when Setup set one).
func New(level Level, out io.Writer) *Auditor {
	return &Auditor{level: level, out: out, logger: global.GetLoggerProvider().Logger(telemetry.Name + "/audit"),
		now: time.Now}
}

// Emit records e, unless the level leaves it out; counted either way.
func (a *Auditor) Emit(ctx context.Context, e Event) {
	if a == nil {
		return
	}
	telemetry.Add(ctx, telemetry.AuditEvents, attribute.String("kind", e.Kind), attribute.String("outcome", e.Outcome))
	switch {
	case a.level == Off:
		return
	case a.level == Changes && (e.Kind == KindRead || e.Kind == KindInspect) && e.Outcome == "ok":
		return
	}
	e.Time, e.Audit = a.now().UTC(), Format
	line, err := json.Marshal(e)
	if err == nil {
		a.mu.Lock()
		_, err = a.out.Write(append(line, '\n'))
		a.mu.Unlock()
	}
	if err != nil {
		telemetry.Add(ctx, telemetry.AuditDropped)
	}
	a.logger.Emit(ctx, record(e))
}

// record is the event as an OpenTelemetry log record: the kind its body, the fields its attributes; the trace
// context comes from ctx.
func record(e Event) otellog.Record {
	var r otellog.Record
	r.SetTimestamp(e.Time)
	r.SetSeverity(otellog.SeverityInfo)
	r.SetEventName("tresor.audit." + e.Kind)
	r.SetBody(attribute.StringValue(e.Kind))
	kv := []attribute.KeyValue{
		attribute.String("tresor.audit", Format),
		attribute.String("tresor.kind", e.Kind),
		attribute.String("tresor.outcome", e.Outcome),
	}
	add := func(k, v string) {
		if v != "" {
			kv = append(kv, attribute.String(k, v))
		}
	}
	add("tresor.reason", e.Reason)
	add("tresor.detail", e.Detail)
	add("tresor.principal", e.Principal)
	add("tresor.actor", e.Actor)
	add("tresor.entry", e.Entry)
	add("tresor.name", e.Name)
	add("tresor.target", e.Target)
	add("tresor.request_id", e.RequestID)
	if len(e.Roles) > 0 {
		kv = append(kv, attribute.StringSlice("tresor.roles", e.Roles))
	}
	if e.Version != 0 {
		kv = append(kv, attribute.Int64("tresor.version", e.Version))
	}
	for i, ref := range e.Refs {
		kv = append(kv, attribute.String(fmt.Sprintf("tresor.references.%d", i), ref.Param+" "+ref.Ref+" "+ref.Version))
	}
	r.AddAttributes(kv...)
	return r
}
