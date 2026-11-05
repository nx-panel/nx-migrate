package marzban

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nx-panel/nx-migrate/internal/bundle"
	"github.com/nx-panel/nx-migrate/internal/source"
)

const wgHex = "0000000000000000000000000000000000000000000000000000000000000001"

// Two VLESS inbounds and a managed WireGuard inbound (PasarGuard v5.5: an
// address list, peers built from the accounts).
const pgCore = `{"inbounds":[
	{"tag":"A","protocol":"vless","port":443,"settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp"}},
	{"tag":"B","protocol":"vless","port":8443,"settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp"}},
	{"tag":"WG","protocol":"wireguard","port":51820,"settings":{"secretKey":"` + wgHex + `","address":["10.8.0.1/24"],"mtu":1420,"peers":[]}}],
	"outbounds":[{"protocol":"freedom","tag":"DIRECT"}]}`

func readPG(t *testing.T) *bundle.Bundle {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/admin/token", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"access_token": "tok"})
	})
	mux.HandleFunc("GET /api/cores", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"cores": []map[string]any{{"id": 1, "name": "main", "type": "xray", "config": json.RawMessage(pgCore)}}})
	})
	mux.HandleFunc("GET /api/admins", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"admins": []any{}})
	})
	mux.HandleFunc("GET /api/groups", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"total": 3, "groups": []map[string]any{
			{"id": 1, "name": "all", "inbound_tags": []string{"A", "B", "WG"}},
			{"id": 2, "name": "a-only", "inbound_tags": []string{"A"}},
			{"id": 3, "name": "off", "inbound_tags": []string{"B"}, "is_disabled": true},
			{"id": 4, "name": "wg", "inbound_tags": []string{"WG"}},
		}})
	})
	user := func(name string, groups []int, extra map[string]any) map[string]any {
		ps := map[string]any{"vless": map[string]any{"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa" + name[:1]}}
		for k, v := range extra {
			ps[k] = v
		}
		return map[string]any{"username": name, "status": "active", "group_ids": groups, "proxy_settings": ps}
	}
	mux.HandleFunc("GET /api/users", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("offset") != "0" {
			writeJSON(w, map[string]any{"users": []any{}})
			return
		}
		writeJSON(w, map[string]any{"total": 3, "users": []map[string]any{
			user("everyone", []int{1}, map[string]any{
				"wireguard": map[string]any{"private_key": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", "peer_ips": []string{"10.8.0.2/32"}},
				"hysteria":  map[string]any{"auth": "hy"},
			}),
			user("aonly", []int{2, 3}, nil),
			user("nobody", []int{3}, nil),
			user("wgonly", []int{4}, nil),
		}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	b, err := reader{flavour: "pasarguard"}.Read(context.Background(), source.Options{
		Channel: source.ChannelAPI, BaseURL: srv.URL, Username: "u", Password: "p",
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func get(t *testing.T, b *bundle.Bundle, id string) (bundle.Item, map[string]any) {
	t.Helper()
	for _, it := range b.Items {
		if it.ID == id {
			var p map[string]any
			_ = json.Unmarshal(it.Payload, &p)
			return it, p
		}
	}
	t.Fatalf("no item %q", id)
	return bundle.Item{}, nil
}

// A managed WireGuard inbound is NX's own per-account endpoint: it lands on
// the template, keeps its key in sing-box's base64, and every account brings
// its own WireGuard key.
func TestPasarGuardWireGuardBecomesAnEndpoint(t *testing.T) {
	b := readPG(t)
	ep, p := get(t, b, "endpoint:WG")
	if ep.Severity == bundle.SevBlocked {
		t.Fatalf("blocked: %v", ep.Notes)
	}
	cfg := p["config"].(map[string]any)
	if cfg["private_key"] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=" || cfg["listen_port"] != float64(51820) ||
		cfg["peers"] != nil || cfg["address"].([]any)[0] != "10.8.0.1/24" {
		t.Errorf("endpoint config = %v", cfg)
	}
	if tpl, _ := get(t, b, "template:core-1"); len(tpl.IDRefs["endpointIds"]) != 1 {
		t.Errorf("endpointIds = %v", tpl.IDRefs["endpointIds"])
	}
	_, u := get(t, b, "client:everyone")
	conf := u["config"].(map[string]any)
	if conf["wgPrivateKey"] != "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=" || conf["password"] != "hy" {
		t.Errorf("config = %v", conf)
	}
}

// PasarGuard reaches inbounds through enabled groups.
func TestPasarGuardGroupsBecomeFilters(t *testing.T) {
	b := readPG(t)
	if _, p := get(t, b, "client:everyone"); p["configFilter"] != nil {
		t.Errorf("everyone needs no filter: %v", p["configFilter"])
	}
	_, p := get(t, b, "client:aonly")
	f, _ := p["configFilter"].(map[string]any)
	in, _ := f["inbounds"].([]any)
	ep, _ := f["endpoints"].([]any)
	if len(in) != 1 || in[0].(map[string]any)["values"].([]any)[0] != "A" || len(ep) != 1 ||
		ep[0].(map[string]any)["op"] != "notIn" || ep[0].(map[string]any)["values"].([]any)[0] != "WG" {
		t.Errorf("aonly filter = %v (the disabled group must not count, and it reached no WireGuard)", f)
	}
	_, p = get(t, b, "client:wgonly")
	f, _ = p["configFilter"].(map[string]any)
	in, _ = f["inbounds"].([]any)
	if len(in) != 1 || in[0].(map[string]any)["op"] != "notIn" || len(in[0].(map[string]any)["values"].([]any)) != 2 || f["endpoints"] != nil {
		t.Errorf("wgonly filter = %v, want off both VLESS inbounds and no endpoint rule", f)
	}
	it, p := get(t, b, "client:nobody")
	if p["configFilter"] != nil || !strings.Contains(strings.Join(it.Notes, " "), "no enabled group") {
		t.Errorf("nobody: filter %v, notes %v", p["configFilter"], it.Notes)
	}
}

// Marzban stores membership as exclusions; its derived `inbounds` cannot be
// trusted for a protocol that excludes everything.
func TestMarzbanExclusionsBecomeFilters(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/admin/token", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"access_token": "tok"})
	})
	mux.HandleFunc("GET /api/core/config", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(pgCore))
	})
	mux.HandleFunc("GET /api/admins", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, []any{}) })
	mux.HandleFunc("GET /api/users", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("offset") != "0" {
			writeJSON(w, map[string]any{"users": []any{}})
			return
		}
		px := map[string]any{"vless": map[string]any{"id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}}
		writeJSON(w, map[string]any{"total": 2, "users": []map[string]any{
			{"username": "full", "status": "active", "proxies": px, "excluded_inbounds": map[string]any{"vless": []string{}},
				"inbounds": map[string]any{"vless": []string{"A", "B"}}},
			{"username": "noB", "status": "active", "proxies": px, "excluded_inbounds": map[string]any{"vless": []string{"B"}},
				"inbounds": map[string]any{"vless": []string{"A", "B"}}},
		}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	b, err := reader{flavour: "marzban"}.Read(context.Background(), source.Options{
		Channel: source.ChannelAPI, BaseURL: srv.URL, Username: "u", Password: "p",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, p := get(t, b, "client:full"); p["configFilter"] != nil {
		t.Errorf("full: %v", p["configFilter"])
	}
	it, _ := get(t, b, "client:noB")
	if it.Detail["limited to"] != "A" {
		t.Errorf("noB detail = %v (excluded_inbounds wins over the derived inbounds)", it.Detail)
	}
}
