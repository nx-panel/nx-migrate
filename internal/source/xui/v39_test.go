package xui

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/nx-panel/nx-migrate/internal/bundle"
	"github.com/nx-panel/nx-migrate/internal/source"
)

// fixtureV39 adds what 3x-ui v3.9–v3.11 changed to the base fixture: the
// calendar-weekly renewal (on the client and on its traffic row), a hysteria
// inbound in today's shape with gecko obfuscation in its finalmask, an XDRIVE
// inbound, and an inbound the operator had switched off.
func fixtureV39(t *testing.T) string {
	t.Helper()
	path := fixture(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`ALTER TABLE client_traffics ADD COLUMN reset_weekday INTEGER`, nil},
		{`ALTER TABLE client_traffics ADD COLUMN reset_max INTEGER`, nil},
		{`ALTER TABLE client_traffics ADD COLUMN reset_count INTEGER`, nil},
		{`ALTER TABLE inbounds ADD COLUMN exclude_from_sub INTEGER`, nil},
		{`INSERT INTO inbounds (id, remark, enable, listen, port, protocol, settings, stream_settings, tag, sniffing, exclude_from_sub)
			VALUES (10,'capped',1,'',9447,'vless',?,'{"network":"tcp"}','inbound-capped','',1)`,
			[]any{`{"clients":[
				{"id":"44444444-4444-4444-4444-444444444444","email":"spent","reset":30,"resetMax":3,"enable":true},
				{"id":"55555555-5555-5555-5555-555555555555","email":"left","reset":30,"resetMax":3,"enable":true}
			],"decryption":"none"}`}},
		{`INSERT INTO client_traffics (inbound_id, enable, email, up, down, expiry_time, total, reset, reset_day, reset_max, reset_count)
			VALUES (10,1,'spent',0,0,0,0,30,0,3,3), (10,1,'left',0,0,0,0,30,0,3,1)`, nil},
		{`INSERT INTO inbounds (id, remark, enable, listen, port, protocol, settings, stream_settings, tag, sniffing)
			VALUES (11,'masque',1,'',9448,'masque',?,'{"network":"tcp"}','inbound-masque','')`,
			[]any{`{"clients":[{"email":"mq","pass":"mq-secret","enable":true}],"address":["10.14.0.1/24"]}`}},
		{`INSERT INTO inbounds (id, remark, enable, listen, port, protocol, settings, stream_settings, tag, sniffing)
			VALUES (6,'weekly',1,'',9444,'vless',?,'{"network":"tcp"}','inbound-9444','')`,
			[]any{`{"clients":[
				{"id":"11111111-1111-1111-1111-111111111111","email":"sunday","resetWeekday":7,"enable":true},
				{"id":"22222222-2222-2222-2222-222222222222","email":"monday","enable":true}
			],"decryption":"none"}`}},
		{`INSERT INTO client_traffics (inbound_id, enable, email, up, down, expiry_time, total, reset, reset_day, reset_weekday)
			VALUES (6,1,'monday',0,0,0,0,0,0,1)`, nil},
		{`INSERT INTO inbounds (id, remark, enable, listen, port, protocol, settings, stream_settings, tag, sniffing)
			VALUES (7,'hy2',1,'',8444,'hysteria',?,?,'inbound-hy','')`,
			[]any{
				`{"version":2,"clients":[{"auth":"hy-secret","email":"hy"}]}`,
				`{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2,"udpIdleTimeout":60},
				  "tlsSettings":{"serverName":"hy.example.com","certificates":[{"certificateFile":"/c.crt","keyFile":"/c.key"}]},
				  "finalmask":{"udp":[{"type":"salamander","settings":{"password":"pw","packetSize":"512-2048"}}]}}`,
			}},
		{`INSERT INTO inbounds (id, remark, enable, listen, port, protocol, settings, stream_settings, tag, sniffing)
			VALUES (8,'xdrive',1,'',9445,'vless',?,'{"network":"xdrive","xdriveSettings":{}}','inbound-xd','')`,
			[]any{`{"clients":[{"id":"33333333-3333-3333-3333-333333333333","email":"xdonly","enable":true}],"decryption":"none"}`}},
		{`INSERT INTO inbounds (id, remark, enable, listen, port, protocol, settings, stream_settings, tag, sniffing)
			VALUES (9,'off',0,'',9446,'vless',?,'{"network":"tcp"}','inbound-off','')`,
			[]any{`{"clients":[],"decryption":"none"}`}},
	} {
		if _, err := db.Exec(q.sql, q.args...); err != nil {
			t.Fatalf("%s: %v", q.sql, err)
		}
	}
	return path
}

func readV39(t *testing.T) *bundle.Bundle {
	t.Helper()
	b, err := source.Read(context.Background(), "3x-ui", source.Options{
		Channel: source.ChannelFile, Path: fixtureV39(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A weekly renewal used to fall through every case and arrive as no renewal
// at all. 3x-ui counts Monday 1 … Sunday 7, NX Sunday 0 … Saturday 6.
func TestWeeklyRenewal(t *testing.T) {
	b := readV39(t)
	for id, day := range map[string]float64{"client:sunday": 0, "client:monday": 1} {
		p := payload(t, find(t, b, id))
		if p["autoReset"] != true || p["resetPeriod"] != "weekly" || p["resetStartDay"] != day {
			t.Errorf("%s: autoReset=%v resetPeriod=%v resetStartDay=%v, want weekly on day %v",
				id, p["autoReset"], p["resetPeriod"], p["resetStartDay"], day)
		}
	}
}

// Today's hysteria inbound names "hysteria" as its network and keeps the
// version under hysteriaSettings; it is hysteria2, and its gecko obfuscation
// must come with it or no client can connect.
func TestHysteria2WithGeckoObfs(t *testing.T) {
	it := find(t, readV39(t), "inbound:7")
	if it.Severity == bundle.SevBlocked {
		t.Fatalf("blocked: %v", it.Notes)
	}
	p := payload(t, it)
	if p["type"] != "hysteria2" {
		t.Fatalf("type = %v, want hysteria2", p["type"])
	}
	obfs, _ := p["config"].(map[string]any)["obfs"].(map[string]any)
	if obfs["type"] != "gecko" || obfs["password"] != "pw" ||
		obfs["min_packet_size"] != float64(512) || obfs["max_packet_size"] != float64(1452) {
		t.Errorf("obfs = %v, want gecko pw 512–1452", obfs)
	}
	var capped, unknown bool
	for _, n := range it.Notes {
		capped = capped || strings.Contains(n, "capped at 1452")
		unknown = unknown || strings.Contains(n, "unknown transport") || strings.Contains(n, "finalmask")
	}
	if !capped || unknown {
		t.Errorf("notes = %v, want the cap said and nothing about a dropped transport or mask", it.Notes)
	}
	cfg := payload(t, find(t, readV39(t), "client:hy"))["config"].(map[string]any)
	if cfg["password"] != "hy-secret" {
		t.Errorf("hysteria auth = %v", cfg["password"])
	}
}

// An inbound in a transport sing-box has no equivalent for used to be created
// as plain TCP, which no client of it could reach.
func TestUnknownTransportIsBlocked(t *testing.T) {
	it := find(t, readV39(t), "inbound:8")
	if it.Severity != bundle.SevBlocked || !strings.Contains(strings.Join(it.Notes, " "), `"xdrive"`) {
		t.Errorf("severity = %s, notes = %v", it.Severity, it.Notes)
	}
}

func TestDisabledInboundIsSaid(t *testing.T) {
	it := find(t, readV39(t), "inbound:9")
	if it.Detail["enabled in 3x-ui"] != "no" || !strings.Contains(strings.Join(it.Notes, " "), "switched off in 3x-ui") {
		t.Errorf("detail = %v, notes = %v", it.Detail, it.Notes)
	}
}

// 3x-ui puts a client on chosen inbounds. An account on every inbound that
// carries clients needs no filter; one on some of them is narrowed to those,
// by tag, so it does not arrive on inbounds it never had.
func TestConfigFilterFollowsInbounds(t *testing.T) {
	b := read(t)
	if f, ok := payload(t, find(t, b, "client:ali"))["configFilter"]; ok {
		t.Errorf("ali is on both inbounds and needs no filter, got %v", f)
	}
	reza := find(t, b, "client:reza kh")
	f, _ := payload(t, reza)["configFilter"].(map[string]any)
	rules, _ := f["inbounds"].([]any)
	if len(rules) != 1 {
		t.Fatalf("reza's filter = %v, want one rule", f)
	}
	rule := rules[0].(map[string]any)
	values, _ := rule["values"].([]any)
	if rule["field"] != "tag" || rule["op"] != "in" || len(values) != 1 || values[0] != "inbound-443" {
		t.Errorf("rule = %v, want tag in [inbound-443]", rule)
	}
	if reza.Detail["limited to"] != "inbound-443" {
		t.Errorf("detail = %v", reza.Detail)
	}
	if _, ok := f["endpoints"]; ok {
		t.Errorf("the endpoints section must stay absent, which restricts nothing: %v", f)
	}
}

// An account the old panel had only on an inbound that cannot come across is
// not limited to it: limited to nothing, it would reach nothing.
func TestOnlyOnABlockedInbound(t *testing.T) {
	it := find(t, readV39(t), "client:xdonly")
	if f, ok := payload(t, it)["configFilter"]; ok {
		t.Errorf("filter = %v, want none", f)
	}
	if !strings.Contains(strings.Join(it.Notes, " "), "only on inbounds that cannot come to NX") {
		t.Errorf("notes = %v", it.Notes)
	}
}

// 3x-ui caps how many times a client may auto-renew. NX renews for as long as
// the cycle is on: a spent cap arrives as no cycle, one with renewals left is
// said.
func TestRenewalCap(t *testing.T) {
	b := readV39(t)
	spent := find(t, b, "client:spent")
	if p := payload(t, spent); p["autoReset"] != false || !strings.Contains(strings.Join(spent.Notes, " "), "all 3") {
		t.Errorf("spent: autoReset %v, notes %v", p["autoReset"], spent.Notes)
	}
	left := find(t, b, "client:left")
	if p := payload(t, left); p["autoReset"] != true || p["resetDays"] != float64(30) ||
		!strings.Contains(strings.Join(left.Notes, " "), "2 more automatic renewal(s) of 3") {
		t.Errorf("left: autoReset %v resetDays %v, notes %v", p["autoReset"], p["resetDays"], left.Notes)
	}
}

func TestExcludedFromSubscriptionsIsSaid(t *testing.T) {
	it := find(t, readV39(t), "inbound:10")
	if it.Detail["in subscriptions"] != "no" || !strings.Contains(strings.Join(it.Notes, " "), "out of its subscriptions") {
		t.Errorf("detail = %v, notes = %v", it.Detail, it.Notes)
	}
}

// A MASQUE inbound stays behind; its client is still a customer, keeps the
// secret (x-ui's pass key) as its password, and is limited to nothing.
func TestMasqueClientComesAcross(t *testing.T) {
	b := readV39(t)
	if find(t, b, "inbound:11").Severity != bundle.SevBlocked {
		t.Error("the MASQUE inbound must stay blocked")
	}
	it := find(t, b, "client:mq")
	p := payload(t, it)
	if it.Severity == bundle.SevBlocked || p["config"].(map[string]any)["password"] != "mq-secret" {
		t.Errorf("severity %s, config %v, notes %v", it.Severity, p["config"], it.Notes)
	}
	if _, ok := p["configFilter"]; ok {
		t.Errorf("filter = %v", p["configFilter"])
	}
}
