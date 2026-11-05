package convert

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// WireGuardKey returns a WireGuard key in the standard base64 sing-box and the
// panel read. Xray and PasarGuard also accept the key as 64 hex characters or
// in URL-safe base64; anything that is not 32 bytes is answered "".
func WireGuardKey(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil {
			return base64.StdEncoding.EncodeToString(b)
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return base64.StdEncoding.EncodeToString(b)
		}
	}
	return ""
}

// ManagedWireGuard converts an Xray WireGuard inbound whose peers a panel
// builds from its accounts (PasarGuard v5.5: one with an `address` list) into
// an NX wireguard endpoint that does the same: a listen port and a prefix,
// no static peers, every account of its templates a peer. ok is false when the
// inbound has no address list, which is a hand-written static-peer inbound.
func ManagedWireGuard(tag string, port int, settings Obj) (cfg Obj, ok bool) {
	addrs, _ := settings["address"].([]any)
	if len(addrs) == 0 {
		return nil, false
	}
	cfg = Obj{"type": "wireguard", "tag": tag, "address": addrs}
	if port > 0 {
		cfg["listen_port"] = port
	}
	if k := WireGuardKey(str(settings["secretKey"])); k != "" {
		cfg["private_key"] = k
	}
	if mtu := num(settings["mtu"]); mtu > 0 {
		cfg["mtu"] = int(mtu)
	}
	return cfg, true
}
