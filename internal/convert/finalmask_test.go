package convert

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nx-panel/nx-migrate/internal/normalize"
)

func hysteria(t *testing.T, mask string) XrayInbound {
	t.Helper()
	stream := decode(t, `{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2},"finalmask":`+mask+`}`)
	return Inbound("hysteria", "", 443, decode(t, `{"version":2,"clients":[{"auth":"a","email":"e"}]}`), stream)
}

// finalmask is where a hysteria2 inbound keeps its obfuscation now; each
// shape it takes has to land as the obfs sing-box reads, or be said.
func TestFinalMask(t *testing.T) {
	for _, tc := range []struct {
		name, mask string
		obfs       map[string]any // nil: no obfs
		note       string         // a note that must be there, "" for none
	}{
		{"salamander", `{"udp":[{"type":"salamander","settings":{"password":"pw"}}]}`,
			map[string]any{"type": "salamander", "password": "pw"}, ""},
		{"gecko range", `{"udp":[{"type":"salamander","settings":{"password":"pw","packetSize":"600-1000"}}]}`,
			map[string]any{"type": "gecko", "password": "pw", "min_packet_size": 600, "max_packet_size": 1000}, ""},
		{"gecko one size", `{"udp":[{"type":"salamander","settings":{"password":"pw","packetSize":900}}]}`,
			map[string]any{"type": "gecko", "password": "pw", "min_packet_size": 900, "max_packet_size": 900}, ""},
		{"gecko over the cap", `{"udp":[{"type":"salamander","settings":{"password":"pw","packetSize":"1500-2048"}}]}`,
			map[string]any{"type": "gecko", "password": "pw", "min_packet_size": 1452, "max_packet_size": 1452}, "capped at 1452"},
		{"unreadable size stays salamander", `{"udp":[{"type":"salamander","settings":{"password":"pw","packetSize":"big"}}]}`,
			map[string]any{"type": "salamander", "password": "pw"}, ""},
		{"no password", `{"udp":[{"type":"salamander","settings":{}}]}`, nil, "salamander without a password"},
		{"other masks", `{"udp":[{"type":"salamander","settings":{"password":"pw"}},{"type":"noise"}],"tcp":[{"type":"fragment"}]}`,
			map[string]any{"type": "salamander", "password": "pw"}, "tcp fragment, udp noise"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := hysteria(t, tc.mask)
			if in.Type != "hysteria2" || in.Blocked != "" {
				t.Fatalf("type = %q, blocked = %q", in.Type, in.Blocked)
			}
			got, _ := in.Config["obfs"].(Obj)
			if fmt.Sprint(map[string]any(got)) != fmt.Sprint(tc.obfs) && !(got == nil && tc.obfs == nil) {
				t.Errorf("obfs = %v, want %v", got, tc.obfs)
			}
			notes := strings.Join(in.Notes, " | ")
			if tc.note != "" && !strings.Contains(notes, tc.note) {
				t.Errorf("notes = %q, want %q in them", notes, tc.note)
			}
			// The certificate note is the fixture's (no files); only the
			// mask's own notes are the subject here.
			if tc.note == "" && (strings.Contains(notes, "finalmask") || strings.Contains(notes, "gecko")) {
				t.Errorf("unexpected notes: %q", notes)
			}
		})
	}

	// Only hysteria2 has an obfs; on any other inbound the mask is said.
	vless := Inbound("vless", "", 443, decode(t, `{"clients":[],"decryption":"none"}`),
		decode(t, `{"network":"tcp","finalmask":{"udp":[{"type":"salamander","settings":{"password":"pw"}}]}}`))
	if vless.Config["obfs"] != nil || !strings.Contains(strings.Join(vless.Notes, " "), "udp salamander") {
		t.Errorf("vless: obfs = %v, notes = %v", vless.Config["obfs"], vless.Notes)
	}
}

// Xray's hysteria is version 2 unless it says 1, wherever the version sits.
func TestHysteriaVersion(t *testing.T) {
	for stream, want := range map[string]string{
		`{"network":"hysteria","hysteriaSettings":{"version":2}}`: "hysteria2",
		`{"network":"hysteria","hysteriaSettings":{}}`:            "hysteria2",
		`{"network":"tcp","version":2}`:                           "hysteria2",
		`{"network":"hysteria","hysteriaSettings":{"version":1}}`: "hysteria",
	} {
		if got, _ := ProtocolFor("hysteria", decode(t, stream)); got != want {
			t.Errorf("%s: %s, want %s", stream, got, want)
		}
	}
}

func TestConfigFilterPayload(t *testing.T) {
	all := []string{"a", "b", "c"}
	for _, tc := range []struct {
		name string
		mine []string
		want []string
	}{
		{"on every inbound", []string{"c", "a", "b", "a"}, nil},
		{"on some", []string{"c", "a", "c"}, []string{"a", "c"}},
		{"on none read", nil, nil},
	} {
		c := Client{SourceID: tc.name, Name: "n"}
		LimitToInbounds(&c, tc.mine, all)
		if fmt.Sprint(c.InboundTags) != fmt.Sprint(tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, c.InboundTags, tc.want)
		}
	}

	// Past the panel's 64 values per rule the account keeps every inbound and
	// is told so, rather than being refused by the panel.
	var mine, every []string
	for i := 0; i < MaxFilterValues+1; i++ {
		mine = append(mine, fmt.Sprintf("in-%d", i))
	}
	every = append(append(every, mine...), "spare")
	c := Client{SourceID: "wide", Name: "wide"}
	LimitToInbounds(&c, mine, every)
	it := ClientItem(c, normalize.NewNamer())
	var p map[string]any
	_ = json.Unmarshal(it.Payload, &p)
	if _, ok := p["configFilter"]; ok || !strings.Contains(strings.Join(it.Notes, " "), "more than the 64") {
		t.Errorf("payload filter = %v, notes = %v", p["configFilter"], it.Notes)
	}
}

// A chained outbound in a transport sing-box lacks used to be created bare,
// dialling a server that speaks something else; it is refused, with the reason.
func TestOutboundInUnknownTransportIsRefused(t *testing.T) {
	_, _, notes, ok := Outbound(decode(t, `{"protocol":"vless","tag":"out",
		"settings":{"vnext":[{"address":"x.example.com","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111"}]}]},
		"streamSettings":{"network":"xdrive"}}`))
	if ok || !strings.Contains(strings.Join(notes, " "), `"xdrive"`) {
		t.Errorf("ok = %v, notes = %v", ok, notes)
	}
}

// Xray moved mKCP's seed and header into finalmask as mkcp-legacy masks; the
// node's mKCP still takes them as seed and header_type. Without the seed every
// packet is undecryptable.
func TestMkcpLegacyMask(t *testing.T) {
	for _, tc := range []struct {
		name, mask   string
		seed, header string
		note         string
	}{
		{"seed and header", `{"udp":[{"type":"mkcp-legacy","settings":{"header":"wechat"}},{"type":"mkcp-legacy","settings":{"value":"s3cr3t"}}]}`,
			"s3cr3t", "wechat-video", ""},
		{"original obfuscation", `{"udp":[{"type":"mkcp-legacy","settings":{}}]}`, "", "", ""},
		{"dns header", `{"udp":[{"type":"mkcp-legacy","settings":{"header":"dns","value":"a.example"}}]}`,
			"", "", "udp mkcp-legacy dns header"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := decode(t, `{"network":"kcp","kcpSettings":{"mtu":1350},"finalmask":`+tc.mask+`}`)
			in := Inbound("vless", "", 443, decode(t, `{"clients":[{"id":"11111111-1111-1111-1111-111111111111","email":"e"}],"decryption":"none"}`), stream)
			tr, _ := in.Config["transport"].(Obj)
			if tr["type"] != "mkcp" || str(tr["seed"]) != tc.seed || str(tr["header_type"]) != tc.header {
				t.Errorf("transport = %v, want seed %q header %q", tr, tc.seed, tc.header)
			}
			notes := strings.Join(in.Notes, " | ")
			if (tc.note == "" && strings.Contains(notes, "finalmask")) || !strings.Contains(notes, tc.note) {
				t.Errorf("notes = %q, want %q", notes, tc.note)
			}
		})
	}
}
