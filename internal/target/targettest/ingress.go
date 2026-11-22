// Package targettest is an NX ingress stand-in for tests: GET and PUT of the
// table, the confirmation, and a route test that walks routes the way the
// panel does (in order; listener, host, excluded host, prefix, then whether
// the service takes the path). It is only imported by tests.
package targettest

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

// Ingress is the fake's state.
type Ingress struct {
	mu        sync.Mutex
	Listeners []map[string]any
	Routes    []map[string]any
	pending   []map[string]any
	// Puts and Confirms count the changes asked for and confirmed.
	Puts, Confirms int
	// PendingOther makes GET report a change of somebody else's waiting.
	PendingOther bool
}

// New is a panel with one listener on 443 and one panel route that serves
// everything on every host — the shape a fresh NX has.
func New() *Ingress {
	return &Ingress{
		Listeners: []map[string]any{{"name": "main", "primary": true, "listenPort": "", "state": map[string]any{"address": "0.0.0.0:443"}}},
		Routes:    []map[string]any{{"name": "panel", "listeners": []any{"main"}, "hosts": []any{}, "prefix": "", "service": "panel"}},
	}
}

// Register mounts the ingress routes.
func (f *Ingress) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/ingress", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		doc := map[string]any{"shaped": true, "listeners": f.Listeners, "routes": f.Routes, "fallbacks": []any{}}
		if f.PendingOther {
			doc["pending"] = map[string]any{"revision": 9, "confirmBy": 1}
		}
		write(w, doc)
	})
	mux.HandleFunc("PUT /api/ingress", func(w http.ResponseWriter, r *http.Request) {
		var doc struct {
			Routes []map[string]any `json:"routes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
			http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.Puts++
		f.pending = doc.Routes
		f.mu.Unlock()
		write(w, map[string]any{"pending": map[string]any{"revision": 1, "confirmBy": 1, "token": "tok-1"}})
	})
	mux.HandleFunc("POST /api/ingress/confirm", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		defer f.mu.Unlock()
		if body.Token != "tok-1" || f.pending == nil {
			http.Error(w, `{"error":"no change is waiting"}`, http.StatusNotFound)
			return
		}
		f.Routes, f.pending = f.pending, nil
		f.Confirms++
		write(w, map[string]any{"revision": 1, "state": "confirmed"})
	})
	mux.HandleFunc("POST /api/ingress/test", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Listener string `json:"listener"`
			Host     string `json:"host"`
			Path     string `json:"path"`
			Ingress  *struct {
				Routes []map[string]any `json:"routes"`
			} `json:"ingress"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		routes := f.Routes
		f.mu.Unlock()
		if req.Ingress != nil {
			routes = req.Ingress.Routes
		}
		write(w, resolve(routes, req.Listener, req.Host, req.Path))
	})
}

// Route finds a route of the saved table by name.
func (f *Ingress) Route(name string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.Routes {
		if r["name"] == name {
			return r
		}
	}
	return nil
}

func resolve(routes []map[string]any, listener, host, path string) map[string]any {
	for _, r := range routes {
		if !contains(strs(r["listeners"]), listener) {
			continue
		}
		hosts := strs(r["hosts"])
		if len(hosts) > 0 && !contains(hosts, host) {
			continue
		}
		if contains(strs(r["excludeHosts"]), host) {
			continue
		}
		prefix, _ := r["prefix"].(string)
		rest := path
		if prefix != "" {
			if !strings.HasPrefix(path, prefix+"/") {
				continue
			}
			rest = strings.TrimPrefix(path, prefix)
		}
		service, _ := r["service"].(string)
		isSub := rest == "/sub" || strings.HasPrefix(rest, "/sub/")
		if service == "sub" && !isSub {
			continue
		}
		// A panel route serves /sub only when its options say so; absent
		// options are the whole panel.
		if opts, ok := r["panel"].(map[string]any); ok && service == "panel" && isSub && opts["sub"] != true {
			continue
		}
		return map[string]any{"outcome": "route", "route": r["name"], "service": service, "path": rest}
	}
	return map[string]any{"outcome": "refused"}
}

func strs(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	if s, ok := v.([]string); ok {
		return s
	}
	return out
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if strings.EqualFold(e, s) {
			return true
		}
	}
	return false
}

func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
