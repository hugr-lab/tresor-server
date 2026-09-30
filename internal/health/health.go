// Package health serves /healthz and /readyz (spec 002). The checks run in the background, so a probe never
// calls the store, a KMS or an identity provider itself. An answer names the failing check, never a value.
package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Check is one readiness condition; its error text is served, so it must name what failed, never a value.
type Check struct {
	Name string
	Run  func(ctx context.Context) error
}

// Checker runs its checks every Interval and keeps the last results.
type Checker struct {
	checks   []Check
	interval time.Duration
	timeout  time.Duration
	log      *slog.Logger

	mu      sync.Mutex
	results map[string]string // name -> "" (ok) or the reason
	ran     bool
}

// New returns a checker; Start runs it.
func New(log *slog.Logger, interval time.Duration, checks ...Check) *Checker {
	return &Checker{checks: checks, interval: interval, timeout: 10 * time.Second, log: log}
}

// Start runs the checks now and then every interval, until ctx ends.
func (c *Checker) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()
		for {
			c.RunOnce(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// RunOnce runs every check once, concurrently.
func (c *Checker) RunOnce(ctx context.Context) {
	results := make(map[string]string, len(c.checks))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, check := range c.checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			checkCtx, cancel := context.WithTimeout(ctx, c.timeout)
			defer cancel()
			reason := ""
			if err := check.Run(checkCtx); err != nil {
				reason = err.Error()
			}
			mu.Lock()
			results[check.Name] = reason
			mu.Unlock()
		}()
	}
	wg.Wait()
	c.mu.Lock()
	for name, reason := range results {
		if before, seen := c.results[name]; (!seen || before != reason) && reason != "" {
			c.log.Warn("not ready", "check", name, "reason", reason)
		} else if seen && before != "" && reason == "" {
			c.log.Info("ready again", "check", name)
		}
	}
	c.results, c.ran = results, true
	c.mu.Unlock()
}

// Ready is the last results: ok only when every check has run and passed.
func (c *Checker) Ready() (bool, map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]string, len(c.checks))
	ok := c.ran
	for _, check := range c.checks {
		reason, seen := c.results[check.Name]
		switch {
		case !seen:
			reason, ok = "not checked yet", false
		case reason != "":
			ok = false
		default:
			reason = "ok"
		}
		out[check.Name] = reason
	}
	return ok, out
}

// Register adds GET /healthz (the process is up) and GET /readyz (every check passed) to mux. Neither needs
// a token.
func (c *Checker) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		write(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		ok, checks := c.Ready()
		status, word := http.StatusOK, "ready"
		if !ok {
			status, word = http.StatusServiceUnavailable, "not ready"
		}
		write(w, status, map[string]any{"status": word, "checks": checks})
	})
}

func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
