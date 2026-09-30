package health

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func get(t *testing.T, h http.Handler, path string) (int, map[string]any, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return rec.Code, body, rec.Body.String()
}

func checks(body map[string]any) map[string]any { return body["checks"].(map[string]any) }

func TestReadiness(t *testing.T) {
	var storeDown, idpDown, idpAnswered atomic.Bool
	logs := &bytes.Buffer{}
	c := New(slog.New(slog.NewTextHandler(logs, nil)), time.Hour,
		Check{Name: "state", Run: func(context.Context) error {
			if storeDown.Load() {
				return errors.New("dial tcp db.internal:5432: connection refused")
			}
			return nil
		}},
		Check{Name: "issuer https://idp", Run: func(context.Context) error {
			if idpDown.Load() {
				return errors.New("idp.internal: 502")
			}
			idpAnswered.Store(true)
			return nil
		}, Soft: idpAnswered.Load})
	mux := http.NewServeMux()
	c.Register(mux)

	if code, _, _ := get(t, mux, "/healthz"); code != 200 {
		t.Fatalf("healthz: %d", code)
	}
	if code, body, _ := get(t, mux, "/readyz"); code != 503 || checks(body)["state"] != "not checked yet" {
		t.Fatalf("readyz before any check: %d %v", code, body)
	}
	c.RunOnce(context.Background())
	if code, _, _ := get(t, mux, "/readyz"); code != 200 {
		t.Fatalf("readyz with every check passing: %d", code)
	}

	// an issuer that answered before and is down now: degraded, still ready
	idpDown.Store(true)
	c.RunOnce(context.Background())
	if code, body, _ := get(t, mux, "/readyz"); code != 200 || checks(body)["issuer https://idp"] != "degraded" {
		t.Fatalf("an issuer's outage after it answered: %d %v", code, body)
	}

	// the store down: unready, and the answer names the check, never the error's text
	storeDown.Store(true)
	c.RunOnce(context.Background())
	code, body, raw := get(t, mux, "/readyz")
	if code != 503 || checks(body)["state"] != "unavailable" {
		t.Fatalf("readyz with the store down: %d %v", code, body)
	}
	if strings.Contains(raw, "db.internal") || strings.Contains(raw, "idp.internal") {
		t.Fatalf("readyz serves an error's text: %s", raw)
	}
	if !strings.Contains(logs.String(), "db.internal") {
		t.Fatal("the error goes to the log")
	}
	if code, _, _ := get(t, mux, "/healthz"); code != 200 {
		t.Fatalf("healthz stays up while not ready: %d", code)
	}

	storeDown.Store(false)
	c.RunOnce(context.Background())
	c.Drain()
	if code, _, _ := get(t, mux, "/readyz"); code != 503 {
		t.Fatalf("readyz while shutting down: %d", code)
	}
}

// an issuer that never answered is fatal: the service cannot verify anyone of it
func TestNeverAnswered(t *testing.T) {
	c := New(slog.New(slog.DiscardHandler), time.Hour,
		Check{Name: "issuer", Run: func(context.Context) error { return errors.New("down") }, Soft: func() bool { return false }})
	c.RunOnce(context.Background())
	if ok, got := c.Ready(); ok || got["issuer"] != "unavailable" {
		t.Fatalf("an issuer that never answered: %v %v", ok, got)
	}
}
