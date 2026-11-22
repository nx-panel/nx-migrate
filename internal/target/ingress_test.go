package target

import (
	"encoding/json"
	"testing"
)

func TestSubBaseOf(t *testing.T) {
	cases := map[string]string{
		"https://sub.nx.com/sub/abc":         "https://sub.nx.com/sub",
		"https://nx.com:8443/p/sub/abc?x=1":  "https://nx.com:8443/p/sub",
		"https://a.sub.nx.com/sub/tok%2Fone": "https://a.sub.nx.com/sub",
		// An escaped slash in the token is part of the token.
		"https://nx.com/sub/a%2Fsub%2Fb": "https://nx.com/sub",
		"https://203.0.113.7/sub/abc":    "https://203.0.113.7/sub",
	}
	for in, want := range cases {
		got, err := subBaseOf(in)
		if err != nil || got != want {
			t.Errorf("subBaseOf(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", "https://nx.com/feed/abc", "http://127.0.0.1:8080/sub/abc", "http://localhost/sub/abc",
		"http://[::1]:2053/sub/abc", "http://172.17.0.2:2053/sub/abc", "http://10.0.0.5/sub/abc",
		"http://192.168.1.10/sub/abc", "http://[fd00::1]/sub/abc", "http://nx-panel:2053/sub/abc",
	} {
		if got, err := subBaseOf(bad); err == nil {
			t.Errorf("subBaseOf(%q) = %q, want an error", bad, got)
		}
	}
}

func ingressOf(t *testing.T, routes ...map[string]any) *Ingress {
	t.Helper()
	in := &Ingress{}
	for _, r := range routes {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		in.Routes = append(in.Routes, raw)
	}
	return in
}

func TestWildcardAndOwnSubAdmins(t *testing.T) {
	in := ingressOf(t,
		map[string]any{"name": "subs", "service": "sub", "hosts": []string{"*.sub.nx.com", "Plain.NX.com."}},
		map[string]any{"name": "shop", "service": "sub", "hosts": []string{"shop.example.com"}, "adminId": 7, "canonical": true},
		map[string]any{"name": "unbound", "service": "sub", "hosts": []string{"x.example.com"}, "adminId": 8},
	)
	if got := in.wildcardFor("nx-sub-ab12.sub.nx.com"); got != "*.sub.nx.com" {
		t.Errorf("wildcardFor(minted) = %q", got)
	}
	for _, h := range []string{"sub.nx.com", "a.b.sub.nx.com", "plain.nx.com"} {
		if got := in.wildcardFor(h); got != "" {
			t.Errorf("wildcardFor(%q) = %q, want none", h, got)
		}
	}
	// A name a route lists by itself is not minted, whatever wildcard is
	// beside it.
	beside := ingressOf(t,
		map[string]any{"name": "subs", "service": "sub", "hosts": []string{"sub.nx.com"}, "canonical": true},
		map[string]any{"name": "panel", "service": "panel", "hosts": []string{"*.nx.com"}},
	)
	if got := beside.wildcardFor("sub.nx.com"); got != "" {
		t.Errorf("wildcardFor(listed) = %q", got)
	}
	if own := in.ownSubAdmins(); !own[7] || own[8] || len(own) != 1 {
		t.Errorf("ownSubAdmins = %v", own)
	}
	if hosts := in.Hosts(); len(hosts) != 4 || hosts[1] != "plain.nx.com" {
		t.Errorf("Hosts = %v", hosts)
	}
}

func TestCanChangeIngress(t *testing.T) {
	cases := []struct {
		id   Identity
		want bool
	}{
		{Identity{Role: "sudo"}, true},
		{Identity{Role: "ops", Base: "sudo"}, true},
		{Identity{Role: "operator"}, false},
		{Identity{Role: "sudo", Scopes: []string{}}, true},
		{Identity{Role: "sudo", Scopes: []string{"users:read"}}, false},
		{Identity{Role: "sudo", Scopes: []string{"ingress:read"}}, false},
		{Identity{Role: "sudo", Scopes: []string{"ingress:read", "ingress:write"}}, true},
	}
	for _, c := range cases {
		if got := c.id.CanChangeIngress(); got != c.want {
			t.Errorf("%+v: CanChangeIngress = %v, want %v", c.id, got, c.want)
		}
	}
}
