// Package health serves /healthz and /readyz (spec 002). The checks run in the background, so a probe never
// calls the store, a KMS or an identity provider itself. The answer serves no error text: a failing check is
// "unavailable" there, and its error goes to the log - it may name hosts, a database, an IdP's reply.
package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Check is one readiness condition.
type Check struct {
	Name string
	Run  func(ctx context.Context) error
	// Soft, when set and true, makes a failure "degraded": reported, but the service stays ready (an issuer
	// whose keys are cached already: one IdP's outage must not take every replica out).
	Soft func() bool
}

const (
	statusOK          = "ok"
	statusUnavailable = "unavailable"
	statusDegraded    = "degraded"
	statusNotChecked  = "not checked yet"
)

// Checker runs its checks every interval and keeps the last results.
type Checker struct {
	checks   []Check
	interval time.Duration
	timeout  time.Duration
	log      *slog.Logger

	mu       sync.Mutex
	results  map[string]string // name -> a status
	draining bool
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

// Drain makes the service unready for good: it is shutting down, and new requests belong elsewhere.
func (c *Checker) Drain() {
	c.mu.Lock()
	c.draining = true
	c.mu.Unlock()
}

// RunOnce runs every check once, concurrently.
func (c *Checker) RunOnce(ctx context.Context) {
	results := make(map[string]string, len(c.checks))
	errs := make(map[string]error, len(c.checks))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, check := range c.checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			checkCtx, cancel := context.WithTimeout(ctx, c.timeout)
			defer cancel()
			status, err := statusOK, check.Run(checkCtx)
			if err != nil {
				status = statusUnavailable
				if check.Soft != nil && check.Soft() {
					status = statusDegraded
				}
			}
			mu.Lock()
			results[check.Name], errs[check.Name] = status, err
			mu.Unlock()
		}()
	}
	wg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, status := range results {
		before := c.results[name]
		switch {
		case status != statusOK && status != before:
			c.log.Warn("readiness: "+status, "check", name, "error", errs[name].Error())
		case status == statusOK && before != "" && before != statusOK:
			c.log.Info("readiness: ok again", "check", name)
		}
	}
	c.results = results
}

// Ready is the last results: ok only when every check has run and none is unavailable.
func (c *Checker) Ready() (bool, map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]string, len(c.checks))
	ok := !c.draining
	for _, check := range c.checks {
		status, seen := c.results[check.Name]
		if !seen {
			status = statusNotChecked
		}
		if status == statusNotChecked || status == statusUnavailable {
			ok = false
		}
		out[check.Name] = status
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
