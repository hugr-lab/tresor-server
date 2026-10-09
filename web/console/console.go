// Package console serves the management console (spec 010): the build embedded under /ui/, an SPA fallback,
// /ui/config.json for the sign-in, and the headers that keep it to itself (CSP, no referrer, no sniffing). The
// console holds no secret: it signs in with the issuers' public clients and calls /v1 and /admin/v1 with the
// administrator's own token.
package console

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"html"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
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
	return handler(cfg, files)
}

// handler serves files: the build.
func handler(cfg Config, files fs.FS) http.Handler {
	index, _ := fs.ReadFile(files, "index.html")
	if missing := missingAssets(files, index); missing != "" {
		// a page whose files are not here (a local build's index.html committed alone) would load nothing
		index = []byte(`<!doctype html><html lang="en"><head><meta charset="utf-8"><base href="/ui/"><title>tresor console</title>` +
			`</head><body><p>The tresor console is not complete in this binary (` + html.EscapeString(missing) +
			` is missing): build it with npm run build in web/console, or use the image.</p></body></html>`)
	}
	// the build names its files relative to <base href>: the service may live below a path
	index = []byte(strings.Replace(string(index), `<base href="/ui/">`, `<base href="`+html.EscapeString(cfg.BasePath)+`/ui/">`, 1))
	if cfg.Issuers == nil {
		cfg.Issuers = []Issuer{}
	}
	config, _ := json.Marshal(map[string]any{"api": cfg.API, "issuers": cfg.Issuers, "environment": cfg.Environment})
	csp := policy(cfg)
	indexTag := etag(index)
	// the microfrontend's module has a fixed name (spec 016): revalidated at each load by its content's ETag, so
	// an upgrade is picked up at once and a load that changed nothing costs a 304
	var moduleTag string
	if module, err := fs.ReadFile(files, "mfe/tresor.js"); err == nil {
		moduleTag = etag(module)
	}
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
				if strings.HasPrefix(name, "assets/") || strings.HasPrefix(name, "mfe/assets/") {
					h.Set("Cache-Control", "public, max-age=31536000, immutable") // hashed names
				}
				if name == "mfe/tresor.js" && moduleTag != "" {
					h.Set("Cache-Control", "no-cache")
					h.Set("ETag", moduleTag) // http.ServeContent answers If-None-Match with 304
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
		h.Set("ETag", indexTag) // http.ServeContent answers If-None-Match with 304
		http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
	})
}

// etag is a strong ETag of content: its SHA-256, hex.
func etag(content []byte) string {
	sum := sha256.Sum256(content)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// assetRef is a file the page names: ./assets/<file>
var assetRef = regexp.MustCompile(`(?:src|href)="\./(assets/[^"]+)"`)

// missingAssets names the first file the page names that the build does not hold; "" when all are there.
func missingAssets(files fs.FS, index []byte) string {
	for _, m := range assetRef.FindAllSubmatch(index, -1) {
		if _, err := fs.Stat(files, string(m[1])); err != nil {
			return string(m[1])
		}
	}
	return ""
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
