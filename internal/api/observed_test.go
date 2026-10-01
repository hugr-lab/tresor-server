package api

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/hugr-lab/tresor-server/internal/audit"
	"github.com/hugr-lab/tresor-server/internal/material"
	azkv "github.com/hugr-lab/tresor-server/internal/material/azurekeyvault"
	"github.com/hugr-lab/tresor-server/internal/traced"
)

// audited gives the fixture an auditor at level, and the lines it writes
func audited(f *fixture, level audit.Level) *bytes.Buffer {
	buf := &bytes.Buffer{}
	f.srv.audit = audit.New(level, buf)
	return buf
}

func events(t *testing.T, buf *bytes.Buffer) []audit.Event {
	t.Helper()
	var out []audit.Event
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("an audit line is no JSON: %v", err)
		}
		if e.Audit != audit.Format || e.Time.IsZero() || e.RequestID == "" {
			t.Fatalf("an event without its format, time or request id: %s", line)
		}
		out = append(out, e)
	}
	return out
}

func find(es []audit.Event, kind, outcome, name string) *audit.Event {
	for i := range es {
		if es[i].Kind == kind && es[i].Outcome == outcome && es[i].Name == name {
			return &es[i]
		}
	}
	return nil
}

// every decision is an event: who, what, how it ended; never material, a token or a value
func TestAudit(t *testing.T) {
	f := newFixture(t, "")
	buf := audited(f, audit.All)
	traceparent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret)
	f.do("PUT", "/v1/secrets/lake/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	f.do("GET", "/v1/secrets/lake", f.alice, "", "traceparent", traceparent)
	f.do("GET", "/v1/secrets/lake", f.carol, "")                          // invisible to carol
	f.do("PUT", "/v1/secrets/lake", f.alice, s3Secret)                    // not alice's to replace
	f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret, "If-Match", `"9"`) // a stale precondition
	f.do("PATCH", "/v1/secrets/lake", f.admin, `{"comment":"x"}`)
	f.do("DELETE", "/v1/secrets/lake/grants/a", f.admin, "")
	f.do("PUT", "/v1/variables/region", f.admin, `{"value":"eu-west-value"}`)
	f.do("DELETE", "/v1/secrets/lake", f.admin, "")
	f.do("GET", "/v1/secrets", f.alice, "") // a list: not audited
	es := events(t, buf)

	created := find(es, audit.KindWrite, "ok", "lake")
	if created == nil || created.Detail != "created" || created.Entry != "secret" || created.Version != 1 ||
		!strings.HasPrefix(created.Principal, "subject:") || len(created.Roles) == 0 {
		t.Fatalf("the create: %+v", created)
	}
	if g := find(es, audit.KindGrant, "ok", "lake"); g == nil || g.Target != "role:analysts" {
		t.Fatalf("the grant: %+v", g)
	}
	read := find(es, audit.KindRead, "ok", "lake")
	if read == nil || read.Version != 2 || read.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || read.SpanID == "" {
		t.Fatalf("the read: %+v", read)
	}
	if d := find(es, audit.KindRead, "denied", "lake"); d == nil || d.Reason != "not_found" {
		t.Fatalf("an invisible read: %+v", d)
	}
	if d := find(es, audit.KindWrite, "denied", "lake"); d == nil || d.Reason != "no_verb" {
		t.Fatalf("a refused write: %+v", d)
	}
	if find(es, audit.KindWrite, "precondition", "lake") == nil {
		t.Fatal("a precondition that failed")
	}
	if find(es, audit.KindAnnotate, "ok", "lake") == nil || find(es, audit.KindDelete, "ok", "lake") == nil {
		t.Fatal("the annotation, the delete")
	}
	if r := find(es, audit.KindRevoke, "ok", "lake"); r == nil || r.Target != "role:analysts" {
		t.Fatalf("the revoke: %+v", r)
	}
	if v := find(es, audit.KindWrite, "ok", "region"); v == nil || v.Entry != "variable" {
		t.Fatalf("a variable's write: %+v", v)
	}
	for _, e := range es {
		if e.Kind == "" || e.Name == "" && e.Kind != audit.KindDelegation {
			t.Fatalf("an event of no audited route: %+v", e)
		}
	}
	all := buf.String()
	for _, secret := range []string{"hunter2", "eu-west-value", f.alice, f.admin, f.carol} {
		if strings.Contains(all, secret) {
			t.Fatal("the audit holds material, a value or a token")
		}
	}
}

// the level: changes leaves out what was read, not what was refused; off records nothing
func TestAuditLevels(t *testing.T) {
	f := newFixture(t, "")
	f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret)
	f.do("PUT", "/v1/secrets/lake/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	buf := audited(f, audit.Changes)
	f.do("GET", "/v1/secrets/lake", f.alice, "")
	f.do("GET", "/v1/secrets/lake", f.carol, "")
	f.do("PATCH", "/v1/secrets/lake", f.admin, `{"comment":"x"}`)
	es := events(t, buf)
	if find(es, audit.KindRead, "ok", "lake") != nil || find(es, audit.KindRead, "denied", "lake") == nil ||
		find(es, audit.KindAnnotate, "ok", "lake") == nil {
		t.Fatalf("changes: %+v", es)
	}
	buf = audited(f, audit.Off)
	f.do("PATCH", "/v1/secrets/lake", f.admin, `{"comment":"y"}`)
	if buf.Len() != 0 {
		t.Fatalf("off: %s", buf)
	}
}

// under a delegation grant: the user is the principal, the server the actor - never the grant's id
func TestAuditDelegation(t *testing.T) {
	f := newFixture(t, "")
	buf := audited(f, audit.All)
	node := f.idp.Service(t, "duckdb-secrets", "node", "analysts")
	f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret)
	f.do("PUT", "/v1/secrets/lake/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	g, r := f.grantFor(node, f.alice)
	if g == "" {
		t.Fatalf("exchange: %d %s", r.status, r.body)
	}
	f.do("GET", "/v1/secrets/lake", node, "", "Delegation", g)
	es := events(t, buf)
	if ex := find(es, audit.KindDelegation, "ok", ""); ex == nil || ex.Detail != "exchanged" {
		t.Fatalf("the exchange: %+v", es)
	}
	read := find(es, audit.KindRead, "ok", "lake")
	if read == nil || read.Actor != "client:node" || !strings.Contains(read.Principal, "alice") {
		t.Fatalf("a read through a server: %+v", read)
	}
	if strings.Contains(buf.String(), g) {
		t.Fatal("the audit holds a delegation grant's id")
	}
}

// spans only under a sampled traceparent: the server's, its parent the caller's, the store's under it
func TestSpansContinueTheCallersTrace(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp), sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.NeverSample())))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev); _ = tp.Shutdown(context.Background()) })
	f := newFixture(t, "")
	f.srv.store = traced.Store(f.srv.store)
	f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret)
	f.do("PUT", "/v1/secrets/lake/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	if n := len(exp.GetSpans()); n != 0 {
		t.Fatalf("%d spans with no traceparent: the service starts none", n)
	}
	f.do("GET", "/v1/secrets/lake", f.alice, "", "traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
	if n := len(exp.GetSpans()); n != 0 {
		t.Fatalf("%d spans under an unsampled traceparent", n)
	}
	f.do("GET", "/v1/secrets/lake", f.alice, "", "traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	spans := exp.GetSpans()
	var server *tracetest.SpanStub
	children := map[string]bool{}
	for i := range spans {
		s := &spans[i]
		if s.SpanContext.TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" {
			t.Fatalf("a span of another trace: %s", s.Name)
		}
		if s.Name == "GET /v1/secrets/{name}" {
			server = s
		} else {
			children[s.Name] = true
		}
		if strings.Contains(s.Name, "lake") {
			t.Fatalf("a name in a span's name: %s", s.Name)
		}
	}
	if server == nil || server.Parent.SpanID().String() != "00f067aa0ba902b7" {
		t.Fatalf("the server span, a child of the caller's: %+v", spans)
	}
	if !children["state.describe"] || !children["state.get"] {
		t.Fatalf("the store's spans under it: %v", children)
	}
}

// a token minted for the caller is an event of its own: the audience, never the token
func TestAuditMint(t *testing.T) {
	f := newFixture(t, "")
	buf := audited(f, audit.All)
	f.do("PUT", "/v1/secrets/echo", f.admin, mintedSecret)
	f.do("PUT", "/v1/secrets/echo/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	r := f.do("GET", "/v1/secrets/echo", f.alice, "")
	if r.status != 200 {
		t.Fatalf("a minted read: %d %s", r.status, r.body)
	}
	es := events(t, buf)
	m := find(es, audit.KindMint, "ok", "echo")
	if m == nil || m.Target != "echo-api" || m.Detail != "minted" || !strings.Contains(m.Principal, "alice") {
		t.Fatalf("the mint: %+v", es)
	}
	var minted map[string]any
	_ = json.Unmarshal(r.body, &minted)
	if token, _ := minted["params"].(map[string]any)["token"].(string); token != "" && strings.Contains(buf.String(), token) {
		t.Fatal("the minted token is in the audit")
	}
}

// minted at a grant's exchange: for the user, under the server - not the server as the principal; the exchange
// names whom the grant is for
func TestAuditMintAtExchange(t *testing.T) {
	f := newFixture(t, "")
	buf := audited(f, audit.All)
	node := f.idp.Service(t, "duckdb-secrets", "node", "nodes")
	f.do("PUT", "/v1/secrets/echo", f.admin, mintedSecret)
	f.do("PUT", "/v1/secrets/echo/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	if g, r := f.grantFor(node, f.alice); g == "" {
		t.Fatalf("exchange: %d %s", r.status, r.body)
	}
	es := events(t, buf)
	m := find(es, audit.KindMint, "ok", "")
	if m == nil || !strings.Contains(m.Principal, "alice") || m.Actor != "client:node" || m.TraceID != "" {
		t.Fatalf("the mint at the exchange: %+v", es)
	}
	ex := find(es, audit.KindDelegation, "ok", "")
	if ex == nil || ex.Detail != "exchanged" || !strings.Contains(ex.Target, "alice") {
		t.Fatalf("the exchange: %+v", ex)
	}
}

// what a request may put in the audit before it is authenticated, or validated, is bounded
func TestAuditBounded(t *testing.T) {
	f := newFixture(t, "")
	buf := audited(f, audit.All)
	long := strings.Repeat("n", 5000)
	f.do("GET", "/v1/secrets/"+long, "", "")
	f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret)
	f.do("PUT", "/v1/secrets/lake/grants/a", f.admin, `{"principal":"`+long+`","verbs":["use"]}`)
	es := events(t, buf)
	if d := find(es, audit.KindRead, "denied", ""); d == nil || d.Reason != "unauthenticated" {
		t.Fatalf("an unauthenticated read with a name no name can be: %+v", es)
	}
	if g := find(es, audit.KindGrant, "invalid", "lake"); g == nil || g.Target != "" {
		t.Fatalf("an invalid grant's principal recorded: %+v", g)
	}
	if strings.Contains(buf.String(), long) {
		t.Fatal("the audit holds what was never a name or a principal")
	}
}

// a reference's read has its own span, under the request's
func TestSpanOfAReference(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp), sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.NeverSample())))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev); _ = tp.Shutdown(context.Background()) })
	f := newFixture(t, "")
	v := &kvSecrets{values: map[string]string{"lake-s3": "hunter2-from-the-vault"}}
	f.srv.material = material.New(traced.Source(azkv.NewWithGetter([]azkv.Allow{{Vault: "corp-vault", Prefixes: []string{"lake-"}}},
		func(string) (azkv.Getter, error) { return v, nil }, azkv.Options{})))
	f.do("PUT", "/v1/secrets/lake", f.admin, refSecret)
	f.do("PUT", "/v1/secrets/lake/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	f.do("GET", "/v1/secrets/lake", f.alice, "", "traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	found := false
	for _, s := range exp.GetSpans() {
		if s.Name == "material.resolve" {
			found = true
			for _, a := range s.Attributes {
				if strings.Contains(a.Value.Emit(), "hunter2") || strings.Contains(a.Value.Emit(), "lake-s3") {
					t.Fatalf("a span's attribute holds what it read: %v", a)
				}
			}
		}
	}
	if !found {
		t.Fatal("no span for the reference")
	}
}
