package convert

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDropClientOnly(t *testing.T) {
	route, dropped := DropClientOnlyRoute(json.RawMessage(`{"final":"direct","find_process":true,"rules":[` +
		`{"process_name":["curl"],"outbound":"block"},` +
		`{"type":"logical","mode":"and","rules":[{"domain":["a"]},{"wifi_ssid":["x"]}],"outbound":"block"},` +
		`{"domain":["b"],"outbound":"direct"}]}`))
	for _, gone := range []string{"find_process", "process_name", "wifi_ssid", `"block"`} {
		if strings.Contains(string(route), gone) {
			t.Errorf("%s survived: %s", gone, route)
		}
	}
	if !strings.Contains(string(route), `"domain":["b"]`) {
		t.Errorf("a clean rule went: %s", route)
	}
	if len(dropped) != 3 {
		t.Errorf("dropped = %v, want three entries", dropped)
	}

	dns, dropped := DropClientOnlyDNS(json.RawMessage(`{"servers":[{"type":"local","tag":"l","neighbor_domain":["lan"]}],"rules":[{"clash_mode":"global","server":"l"}]}`))
	if strings.Contains(string(dns), "neighbor_domain") || strings.Contains(string(dns), "clash_mode") || len(dropped) != 2 {
		t.Errorf("dns = %s, dropped = %v", dns, dropped)
	}

	clean := json.RawMessage(`{"rules":[{"domain":["b"],"outbound":"direct"}]}`)
	if got, dropped := DropClientOnlyRoute(clean); string(got) != string(clean) || dropped != nil {
		t.Errorf("a clean route was rewritten: %s %v", got, dropped)
	}
}

// The panel also refuses a dial strategy on a rule's action, a client-only
// condition inside an inline rule set, and a dial strategy on an outbound or
// endpoint; each is stripped the way the panel would prune it.
func TestDropClientOnlyOptionsAndDial(t *testing.T) {
	route, dropped := DropClientOnlyRoute(json.RawMessage(`{"rules":[` +
		`{"domain":["a"],"action":"route","outbound":"x","network_strategy":"hybrid","fallback_network_type":["cellular"]}],` +
		`"rule_set":[{"type":"inline","tag":"i","rules":[{"wifi_ssid":["home"]},{"domain":["c"]}]}]}`))
	for _, gone := range []string{"network_strategy", "fallback_network_type", "wifi_ssid"} {
		if strings.Contains(string(route), gone) {
			t.Errorf("%s survived: %s", gone, route)
		}
	}
	for _, kept := range []string{`"domain":["a"]`, `"domain":["c"]`, `"outbound":"x"`} {
		if !strings.Contains(string(route), kept) {
			t.Errorf("%s went: %s", kept, route)
		}
	}
	if len(dropped) != 3 {
		t.Errorf("dropped = %v, want three entries", dropped)
	}

	cfg := map[string]any{"type": "direct", "network_strategy": "default", "network_type": []any{"wifi"}, "fallback_delay": "300ms"}
	if got := DropClientOnlyDial(cfg); len(got) != 2 || cfg["fallback_delay"] == nil || cfg["network_strategy"] != nil {
		t.Errorf("dropped = %v, left %v", got, cfg)
	}
}
