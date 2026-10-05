// Package console serves the management console (spec 010): the build embedded under /ui/, an SPA fallback,
// /ui/config.json for the sign-in, and the headers that keep it to itself (CSP, no referrer, no sniffing). The
// console holds no secret: it signs in with the issuers' public clients and calls /v1 and /admin/v1 with the
// administrator's own token.
package console

import (
	"embed"
	"encoding/json"
	"html"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// dist is the console's build; `go build` alone embeds a placeholder page.
//
//go:embed all:dist
var dist embed.FS

// Issuer is what the sign-in needs of an issuer: its public client.
type Issuer struct {
	Issuer            string   `json:"issuer"`
	ClientID          string   `json:"client_id"`
	Scopes            []string `json:"scopes,omitempty"`
	Audience          string   `json:"audience"`
	AudienceParameter bool     `json:"audience_parameter,omitempty"`
}

// Config is what the console is told at /ui/config.json, and what its headers allow.
type Config struct {
	BasePath       string   // public_url's path ("" at the root)
	API            string   // public_url
	Issuers        []Issuer // those with a public client (client_id): people sign in with them
	Environment    string   // the badge; "" none
	FrameAncestors []string // pages that may frame /ui/; none by default
	ConnectSrc     []string // more origins the sign-in calls (an IdP's endpoints on another host)
}

// Handler serves GET /ui/... (the caller has stripped public_url's path).
func Handler(cfg Config) http.Handler {
	files, _ := fs.Sub(dist, "dist")
	index, _ := fs.ReadFile(files, "index.html")
	// the build names its files relative to <base href>: the service may live below a path
	index = []byte(strings.Replace(string(index), `<base href="/ui/">`, `<base href="`+html.EscapeString(cfg.BasePath)+`/ui/">`, 1))
	if cfg.Issuers == nil {
		cfg.Issuers = []Issuer{}
	}
	config, _ := json.Marshal(map[string]any{"api": cfg.API, "issuers": cfg.Issuers, "environment": cfg.Environment})
	csp := policy(cfg)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rest, ok := strings.CutPrefix(r.URL.Path, "/ui/")
		if !ok {
			http.Redirect(w, r, cfg.BasePath+"/ui/", http.StatusMovedPermanently)
			return
		}
		switch {
		case rest == "config.json":
			h.Set("Content-Type", "application/json")
			h.Set("Cache-Control", "no-store")
			_, _ = w.Write(config)
			return
		case rest != "" && !strings.HasSuffix(rest, "/") && rest != "index.html":
			name := path.Clean(rest)
			if info, err := fs.Stat(files, name); err == nil && !info.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					h.Set("Cache-Control", "public, max-age=31536000, immutable") // hashed names
				}
				http.ServeFileFS(w, r, files, name)
				return
			}
			if path.Ext(name) != "" {
				http.NotFound(w, r) // a missing file, not a route of the app
				return
			}
		}
		// a route of the app: the page, which routes itself
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	})
}

// policy is the console's Content-Security-Policy: its own files only, and the issuers' origins (with
// ui.connect_src's) for the sign-in's requests - token, keys, user info. The token is renewed by a refresh, never
// in a hidden frame: no frame-src.
func policy(cfg Config) string {
	connect := []string{"'self'"}
	seen := map[string]bool{}
	for _, is := range cfg.Issuers {
		if u, err := url.Parse(is.Issuer); err == nil && u.Host != "" {
			if o := u.Scheme + "://" + u.Host; !seen[o] {
				seen[o] = true
				connect = append(connect, o)
			}
		}
	}
	for _, o := range cfg.ConnectSrc {
		if !seen[o] {
			seen[o] = true
			connect = append(connect, o)
		}
	}
	ancestors := "'none'"
	if len(cfg.FrameAncestors) > 0 {
		ancestors = strings.Join(cfg.FrameAncestors, " ")
	}
	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self'",
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src " + strings.Join(connect, " "),
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
		"frame-ancestors " + ancestors,
	}, "; ")
}
