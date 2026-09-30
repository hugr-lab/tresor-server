package health

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func get(t *testing.T, h http.Handler, path string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return rec.Code, body
}

func TestReadiness(t *testing.T) {
	var storeDown atomic.Bool
	c := New(slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour,
		Check{Name: "state", Run: func(context.Context) error {
			if storeDown.Load() {
				return errors.New("the store does not answer")
			}
			return nil
		}},
		Check{Name: "issuers", Run: func(context.Context) error { return nil }})
	mux := http.NewServeMux()
	c.Register(mux)

	if code, _ := get(t, mux, "/healthz"); code != 200 {
		t.Fatalf("healthz: %d", code)
	}
	if code, body := get(t, mux, "/readyz"); code != 503 || body["checks"].(map[string]any)["state"] != "not checked yet" {
		t.Fatalf("readyz before any check: %d %v", code, body)
	}
	c.RunOnce(context.Background())
	if code, _ := get(t, mux, "/readyz"); code != 200 {
		t.Fatalf("readyz with every check passing: %d", code)
	}
	storeDown.Store(true)
	c.RunOnce(context.Background())
	code, body := get(t, mux, "/readyz")
	if code != 503 || body["checks"].(map[string]any)["state"] != "the store does not answer" ||
		body["checks"].(map[string]any)["issuers"] != "ok" {
		t.Fatalf("readyz with the store down: %d %v", code, body)
	}
	if code, _ := get(t, mux, "/healthz"); code != 200 {
		t.Fatalf("healthz stays up while not ready: %d", code)
	}
}
