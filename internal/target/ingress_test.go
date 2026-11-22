package target

import "testing"

func TestSubBaseOf(t *testing.T) {
	cases := map[string]string{
		"https://sub.nx.com/sub/abc":         "https://sub.nx.com/sub",
		"https://nx.com:8443/p/sub/abc?x=1":  "https://nx.com:8443/p/sub",
		"https://a.sub.nx.com/sub/tok%2Fone": "https://a.sub.nx.com/sub",
	}
	for in, want := range cases {
		got, err := subBaseOf(in)
		if err != nil || got != want {
			t.Errorf("subBaseOf(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "https://nx.com/feed/abc", "http://127.0.0.1:8080/sub/abc", "http://localhost/sub/abc"} {
		if got, err := subBaseOf(bad); err == nil {
			t.Errorf("subBaseOf(%q) = %q, want an error", bad, got)
		}
	}
}
