package api

import (
	"net/http"
	"slices"
	"strings"
)

// cors answers browsers (tresor's protocol, Browsers; spec 022) for two lists of origins, each its own owner's
// choice:
//   - console: the hosts that mount the console as a microfrontend (ui.allowed_origins, spec 010) - its module and
//     fonts (/ui/mfe/, GET only), /v1 and /admin/v1;
//   - pages: web pages running tresor in DuckDB-wasm (cors.allowed_origins) - discovery and /v1.
//
// No cookie is ever sent or honoured, and no credentials allowed: the bearer token is the only credential. Any
// other origin gets no CORS header, so a browser keeps its pages from reading an answer.
func cors(console, pages []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		p := r.URL.Path
		mfe := strings.HasPrefix(p, "/ui/mfe/")
		v1 := strings.HasPrefix(p, "/v1/")
		admin := strings.HasPrefix(p, "/admin/v1/")
		discovery := p == "/.well-known/duckdb-secrets"
		if mfe || v1 || admin || discovery {
			w.Header().Add("Vary", "Origin") // an answer depends on it, whether or not this request sent one
		}
		allowed := origin != "" && ((slices.Contains(console, origin) && (mfe || v1 || admin)) ||
			(slices.Contains(pages, origin) && (v1 || discovery)))
		if !allowed {
			if origin != "" && (mfe || v1 || admin || discovery) && r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent) // a preflight answered without permission: the browser refuses
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		if mfe {
			next.ServeHTTP(w, r) // files: a module and fonts, read with GET; nothing to expose, no preflight
			return
		}
		h.Set("Access-Control-Expose-Headers", "ETag, X-Request-Id")
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			h.Set("Access-Control-Allow-Methods", "GET, PUT, PATCH, POST, DELETE")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Delegation, If-Match, If-None-Match, traceparent")
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
