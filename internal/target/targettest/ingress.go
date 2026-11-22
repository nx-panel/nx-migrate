// Package targettest is an NX ingress stand-in for tests: GET and PUT of the
// table, the confirmation, and a route test that walks routes the way the
// panel does (in order; listener, host, excluded host, prefix, then whether
// the service takes the path). It is only imported by tests.
package targettest

import (
	"encoding/json"
	"net"
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
	// Warnings and Restart are what the answer to a change carries.
	Warnings []map[string]any
	Restart  bool
	// NoCert are the names a TLS handshake is refused for, as on a listener
	// that rejects names it holds no certificate for.
	NoCert map[string]bool
	// PutStatus, when set, is what a change is answered with instead
	// (428 for a stale second factor, 400 for a refused table).
	PutStatus int
	// Busy is how many confirmations are answered 409 ("still being
	// applied") before one is taken.
	Busy int
	// OnPut runs after a change is saved, before it is answered; OnTest
	// before a route test is answered; OnConfirm before a confirmation is.
	OnPut, OnTest, OnConfirm func()
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
		if f.PutStatus != 0 {
			http.Error(w, `{"error":"refused"}`, f.PutStatus)
			return
		}
		// The panel's validation of a route's hosts, as far as it matters
		// here: a host name or a bare IP, never a URL or a host:port.
		for _, r := range doc.Routes {
			for _, h := range append(strs(r["hosts"]), strs(r["excludeHosts"])...) {
				if strings.ContainsAny(h, "/ ") || (strings.Contains(h, ":") && net.ParseIP(h) == nil) {
					http.Error(w, `{"error":"`+h+` is not a host name"}`, http.StatusBadRequest)
					return
				}
			}
		}
		f.mu.Lock()
		f.Puts++
		f.pending = doc.Routes
		onPut := f.OnPut
		f.mu.Unlock()
		if onPut != nil {
			onPut()
		}
		write(w, map[string]any{"pending": map[string]any{"revision": 1, "confirmBy": 1, "token": "tok-1"},
			"warnings": f.Warnings, "restart": f.Restart})
	})
	mux.HandleFunc("POST /api/ingress/confirm", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		onConfirm := f.OnConfirm
		f.mu.Unlock()
		if onConfirm != nil {
			onConfirm()
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.Busy > 0 && f.pending != nil {
			f.Busy--
			http.Error(w, `{"error":"the change is still being applied; ask again"}`, http.StatusConflict)
			return
		}
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
			TLS      bool   `json:"tls"`
			SNI      string `json:"sni"`
			Ingress  *struct {
				Routes []map[string]any `json:"routes"`
			} `json:"ingress"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		onTest := f.OnTest
		f.mu.Unlock()
		if onTest != nil {
			onTest()
		}
		f.mu.Lock()
		routes, refused := f.Routes, req.TLS && f.NoCert[req.SNI]
		f.mu.Unlock()
		if refused {
			write(w, map[string]any{"outcome": "refused", "closed": "unknown-sni"})
			return
		}
		if req.Ingress != nil {
			routes = req.Ingress.Routes
		}
		write(w, resolve(routes, req.Listener, req.Host, req.Path))
	})
}

// Edit changes the saved table, as another admin would.
func (f *Ingress) Edit(change func(routes []map[string]any) []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Routes = change(f.Routes)
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
	// As the panel reads a Host header: no port, no trailing dot.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	for _, r := range routes {
		if !contains(strs(r["listeners"]), listener) {
			continue
		}
		hosts := strs(r["hosts"])
		if len(hosts) > 0 && !matches(hosts, host) {
			continue
		}
		if matches(strs(r["excludeHosts"]), host) {
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

// matches reports whether host is one of the entries; "*.x" is exactly one
// label under x, as the panel reads it.
func matches(entries []string, host string) bool {
	for _, e := range entries {
		if suffix, ok := strings.CutPrefix(strings.ToLower(e), "*."); ok {
			label, under := strings.CutSuffix(strings.ToLower(host), "."+suffix)
			if under && label != "" && !strings.Contains(label, ".") {
				return true
			}
			continue
		}
		if strings.EqualFold(e, host) {
			return true
		}
	}
	return false
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
