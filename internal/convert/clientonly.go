package convert

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Client-only sing-box options: they read state only a client has — the
// process or app behind a connection, the Wi-Fi network, the platform's
// network monitor, a LAN neighbour, a Clash mode. NX offers none of them
// (the Panel's docs/product.md decision 29): the Panel refuses to save a
// template carrying one and the node refuses a config naming one. A panel
// whose routing was also run on clients (s-ui) may carry them, so they are
// dropped on import and the import says so.
var (
	clientOnlyRuleKeys = []string{
		"process_name", "process_path", "process_path_regex",
		"package_name", "package_name_regex", "user", "user_id",
		"wifi_ssid", "wifi_bssid", "network_type", "network_is_expensive",
		"network_is_constrained", "default_interface_address",
		"source_mac_address", "source_hostname", "clash_mode",
	}
	clientOnlyRouteKeys = []string{
		"find_process", "find_neighbor", "dhcp_lease_files", "override_android_vpn",
		"default_network_strategy", "default_network_type",
		"default_fallback_network_type", "default_fallback_delay",
	}
	// Options of a route rule's action rather than conditions: a dial
	// strategy only a platform interface follows. The rule keeps its match and
	// loses only these, as the panel prunes them.
	clientOnlyRuleActionKeys = []string{"network_strategy", "fallback_network_type"}
	// Dial options of an outbound or endpoint, which the panel refuses on
	// save. fallback_delay is not one: it is also a server's own IPv4/IPv6
	// race delay.
	clientOnlyDialKeys = []string{"network_strategy", "network_type", "fallback_network_type"}
)

// DropClientOnlyDial removes the client-only dial options from one outbound
// or endpoint document and names what went. The panel refuses to save an item
// carrying one.
func DropClientOnlyDial(cfg map[string]any) []string {
	var dropped []string
	for _, key := range clientOnlyDialKeys {
		if _, ok := cfg[key]; ok {
			delete(cfg, key)
			dropped = append(dropped, key)
		}
	}
	return dropped
}

// DropClientOnlyRoute removes the client-only options from a sing-box route
// block and reports what went. A rule naming a client-only condition anywhere
// in it is dropped whole: stripping only the condition would widen it, and on a
// server such a rule never matched.
func DropClientOnlyRoute(route json.RawMessage) (json.RawMessage, []string) {
	return dropClientOnly(route, "route", clientOnlyRouteKeys, false)
}

// DropClientOnlyDNS does the same for a dns block: its rules, and a local
// server's neighbour domains.
func DropClientOnlyDNS(dns json.RawMessage) (json.RawMessage, []string) {
	return dropClientOnly(dns, "dns", nil, true)
}

func dropClientOnly(raw json.RawMessage, name string, blockKeys []string, servers bool) (json.RawMessage, []string) {
	var block map[string]any
	if json.Unmarshal(raw, &block) != nil {
		return raw, nil
	}
	var dropped []string
	for _, key := range blockKeys {
		if _, ok := block[key]; ok {
			delete(block, key)
			dropped = append(dropped, name+"."+key)
		}
	}
	if rules, ok := block["rules"].([]any); ok {
		kept, gone := dropClientOnlyRules(name+".rules", rules)
		dropped = append(dropped, gone...)
		if name == "route" {
			for i, rule := range kept {
				obj, ok := rule.(map[string]any)
				if !ok {
					continue
				}
				for _, key := range clientOnlyRuleActionKeys {
					if _, has := obj[key]; has {
						delete(obj, key)
						dropped = append(dropped, fmt.Sprintf("%s.rules[%d].%s", name, i, key))
					}
				}
			}
		}
		block["rules"] = kept
	}
	// An inline rule set carries the same match conditions, and the panel
	// refuses a client-only one there too.
	if sets, ok := block["rule_set"].([]any); ok && name == "route" {
		for i, set := range sets {
			obj, ok := set.(map[string]any)
			if !ok {
				continue
			}
			if rules, ok := obj["rules"].([]any); ok {
				kept, gone := dropClientOnlyRules(fmt.Sprintf("%s.rule_set[%d].rules", name, i), rules)
				obj["rules"] = kept
				dropped = append(dropped, gone...)
			}
		}
	}
	if servers {
		if list, ok := block["servers"].([]any); ok {
			for i, srv := range list {
				if obj, ok := srv.(map[string]any); ok {
					if _, has := obj["neighbor_domain"]; has {
						delete(obj, "neighbor_domain")
						dropped = append(dropped, fmt.Sprintf("%s.servers[%d].neighbor_domain", name, i))
					}
				}
			}
		}
	}
	if len(dropped) == 0 {
		return raw, nil
	}
	out, err := json.Marshal(block)
	if err != nil {
		return raw, nil
	}
	return out, dropped
}

// dropClientOnlyRules keeps the rules that name no client-only condition.
// A rule naming one goes whole: stripping only the condition would widen it.
func dropClientOnlyRules(path string, rules []any) (kept []any, dropped []string) {
	kept = make([]any, 0, len(rules))
	for i, rule := range rules {
		if keys := clientOnlyIn(rule); len(keys) > 0 {
			dropped = append(dropped, fmt.Sprintf("%s[%d] (%s)", path, i, strings.Join(keys, ", ")))
			continue
		}
		kept = append(kept, rule)
	}
	return kept, dropped
}

// clientOnlyIn lists the client-only conditions a rule sets, nested logical
// rules included.
func clientOnlyIn(rule any) []string {
	obj, ok := rule.(map[string]any)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for _, key := range clientOnlyRuleKeys {
		if v, ok := obj[key]; ok && !emptyValue(v) {
			seen[key] = true
		}
	}
	if nested, ok := obj["rules"].([]any); ok {
		for _, inner := range nested {
			for _, key := range clientOnlyIn(inner) {
				seen[key] = true
			}
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func emptyValue(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case string:
		return x == ""
	case float64:
		return x == 0
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}
