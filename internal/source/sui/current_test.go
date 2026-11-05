package sui

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nx-panel/nx-migrate/internal/bundle"
	"github.com/nx-panel/nx-migrate/internal/source"
)

// fixtureCurrent adds what s-ui and the panel changed since the base fixture:
// the per-inbound switch (s-ui after v1.6.7), a second inbound only one client
// is on, and an outbound and an endpoint carrying the client-only dial
// strategy the panel refuses on save.
func fixtureCurrent(t *testing.T) string {
	t.Helper()
	path := fixture(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`ALTER TABLE inbounds ADD COLUMN enable INTEGER`,
		`UPDATE inbounds SET enable = 1`,
		`INSERT INTO inbounds (id, type, tag, tls_id, addrs, out_json, options, enable) VALUES
			(2,'trojan','trojan in',0,'[]','','{"listen":"::","listen_port":8443}',0)`,
		`UPDATE clients SET inbounds = '[1,2]' WHERE name = 'ali'`,
		`INSERT INTO outbounds (id, type, tag, options) VALUES
			(2,'socks','up','{"server":"10.0.0.1","server_port":1080,"network_strategy":"hybrid","fallback_delay":"300ms"}')`,
		`INSERT INTO endpoints (id, type, tag, options, ext) VALUES
			(2,'wireguard','wg-out','{"network_type":["wifi"],"mtu":1408}','{}')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	return path
}

func readCurrent(t *testing.T) *bundle.Bundle {
	t.Helper()
	b, err := source.Read(context.Background(), "s-ui", source.Options{
		Channel: source.ChannelFile, Path: fixtureCurrent(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDisabledInboundIsSaid(t *testing.T) {
	b := readCurrent(t)
	off := find(t, b, "inbound:2")
	if off.Detail["enabled in s-ui"] != "no" || !strings.Contains(strings.Join(off.Notes, " "), "switched off in s-ui") {
		t.Errorf("detail = %v, notes = %v", off.Detail, off.Notes)
	}
	if on := find(t, b, "inbound:1"); on.Detail["enabled in s-ui"] != "" {
		t.Errorf("a live inbound was marked off: %v", on.Detail)
	}
	// A database from before the column: nothing is marked.
	if it := find(t, read(t), "inbound:1"); it.Detail["enabled in s-ui"] != "" {
		t.Errorf("no column, but marked: %v", it.Detail)
	}
}

// ali is on both inbounds and needs no filter; reza only on the first, and is
// narrowed to it by tag.
func TestConfigFilterFollowsInbounds(t *testing.T) {
	b := readCurrent(t)
	ali, reza := find(t, b, "client:1"), find(t, b, "client:2")
	if f, ok := payload(t, ali)["configFilter"]; ok {
		t.Errorf("ali needs no filter, got %v", f)
	}
	f, _ := payload(t, reza)["configFilter"].(map[string]any)
	rules, _ := f["inbounds"].([]any)
	if len(rules) != 1 {
		t.Fatalf("reza's filter = %v", f)
	}
	rule := rules[0].(map[string]any)
	values, _ := rule["values"].([]any)
	tag := find(t, b, "inbound:1").Name
	if rule["field"] != "tag" || rule["op"] != "in" || len(values) != 1 || values[0] != tag {
		t.Errorf("rule = %v, want tag in [%s]", rule, tag)
	}
	// With one inbound, nobody can be on only some of them.
	for _, it := range read(t).Items {
		if it.Kind == bundle.KindClient {
			if f, ok := payload(t, it)["configFilter"]; ok {
				t.Errorf("%s: filter %v on a one-inbound panel", it.ID, f)
			}
		}
	}
}

func TestClientOnlyDialIsDropped(t *testing.T) {
	b := readCurrent(t)
	for id, gone := range map[string]string{"outbound:2": "network_strategy", "endpoint:2": "network_type"} {
		it := find(t, b, id)
		cfg := payload(t, it)["config"].(map[string]any)
		if _, ok := cfg[gone]; ok {
			t.Errorf("%s still carries %s: %v", id, gone, cfg)
		}
		if !strings.Contains(strings.Join(it.Notes, " "), gone) {
			t.Errorf("%s: the drop was not said: %v", id, it.Notes)
		}
	}
	if cfg := payload(t, find(t, b, "outbound:2"))["config"].(map[string]any); cfg["fallback_delay"] != "300ms" {
		t.Errorf("fallback_delay is a server option and must stay: %v", cfg)
	}
}

// Since s-ui v1.6.3 every client carries a snell userkey, and hysteria2, tuic
// and anytls keep passwords of their own; NX keys them all with one password,
// so a secret that differs is named rather than silently replaced.
func TestEverySecretIsWeighed(t *testing.T) {
	_, pw, _, _, conflicts := credentials(json.RawMessage(`{"snell":{"name":"a","userkey":"sk"}}`))
	if pw != "sk" || len(conflicts) != 0 {
		t.Errorf("snell only: password %q, conflicts %v", pw, conflicts)
	}
	_, pw, _, _, conflicts = credentials(json.RawMessage(`{"trojan":{"password":"tp"},
		"hysteria2":{"password":"hp"},"anytls":{"password":"tp"},"snell":{"userkey":"sk"}}`))
	if pw != "tp" || strings.Join(conflicts, ",") != "hysteria2,snell" {
		t.Errorf("password %q, conflicts %v", pw, conflicts)
	}
}
