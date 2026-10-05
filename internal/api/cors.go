package api

import (
	"net/http"
	"slices"
	"strings"
)

// cors lets the console, mounted as a microfrontend on a configured host (ui.allowed_origins, spec 010), load its
// module and fonts (/ui/mfe/, GET only) and call /v1 and /admin/v1 with its bearer token. No cookie is ever sent or honoured; any other origin gets no CORS
// header, so a browser keeps its pages from reading an answer.
func cors(origins []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		mfe := strings.HasPrefix(r.URL.Path, "/ui/mfe/")
		api := strings.HasPrefix(r.URL.Path, "/v1/") || strings.HasPrefix(r.URL.Path, "/admin/v1/") || mfe
		if api {
			w.Header().Add("Vary", "Origin") // an answer depends on it, whether or not this request sent one
		}
		if origin == "" || !api {
			next.ServeHTTP(w, r)
			return
		}
		if !slices.Contains(origins, origin) {
			if r.Method == http.MethodOptions {
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
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, If-Match, If-None-Match, traceparent")
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
