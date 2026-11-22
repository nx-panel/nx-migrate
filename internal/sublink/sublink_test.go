package sublink

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nx-panel/nx-migrate/internal/bundle"
	"github.com/nx-panel/nx-migrate/internal/target"
	"github.com/nx-panel/nx-migrate/internal/target/targettest"
)

func TestFromURL(t *testing.T) {
	cases := []struct {
		in   string
		want Old
		ok   bool
	}{
		{"https://sub.old.com:2096/k3j9x0q2/", Old{Scheme: "https", Host: "sub.old.com", Port: 2096, Path: "/k3j9x0q2"}, true},
		{"https://Sub.Old.com/sub/", Old{Scheme: "https", Host: "sub.old.com", Path: "/sub"}, true},
		{"/sub/", Old{Scheme: "https", Path: "/sub"}, true},
		{"sub/", Old{}, false},
		{"ftp://x/sub/", Old{}, false},
		{"", Old{}, false},
	}
	for _, c := range cases {
		got, ok := FromURL(c.in, "", "")
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("FromURL(%q) = %+v, %v; want %+v, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestFromLinkDropsTheToken(t *testing.T) {
	got, ok := FromLink("https://sub.old.com:8443/sub/dXNlcjEsMTcwMDAwMDAwMA.abc123?x=1", "subscription")
	if !ok || got.Host != "sub.old.com" || got.Port != 8443 || got.Path != "/sub" {
		t.Fatalf("FromLink = %+v, %v", got, ok)
	}
	if got, ok := FromLink("/sub/abc", ""); !ok || got.Host != "" || got.Path != "/sub" {
		t.Errorf("a relative Marzban link = %+v, %v", got, ok)
	}
}

func TestExampleAndRouteName(t *testing.T) {
	o := Old{Scheme: "https", Host: "sub.old.com", Port: 2096, Path: "/k3j9x0q2", Format: "xray"}
	if got := o.Example(); got != "https://sub.old.com:2096/k3j9x0q2/{token}" {
		t.Errorf("Example = %q", got)
	}
	if got := o.RouteName(); got != "old-sub-sub-old-com-2096-k3j9x0q2-xray" {
		t.Errorf("RouteName = %q", got)
	}
	hostless := Old{Scheme: "http", Port: 2096, Path: "/sub"}
	if got := hostless.Example(); got != "http://{server}:2096/sub/{token}" {
		t.Errorf("hostless Example = %q", got)
	}
	if got := hostless.RouteName(); got != "old-sub-any-host-2096-sub" {
		t.Errorf("hostless RouteName = %q", got)
	}
}

// A path at the root, or one NX cannot spell as a prefix, is shown and
// explained but never applied.
func TestUnroutablePathsAreBlocked(t *testing.T) {
	for _, p := range []string{"", "/a b", "/x/../y"} {
		it := Old{Host: "h", Path: p}.Item()
		if it.Severity != bundle.SevBlocked {
			t.Errorf("path %q: severity = %s, want blocked", p, it.Severity)
		}
	}
	if it := (Old{Host: "h", Path: "/k3j9x0q2"}).Item(); it.Severity == bundle.SevBlocked {
		t.Errorf("a random 3x-ui path was blocked: %v", it.Notes)
	}
}

func TestAddKeepsOneItemPerAddress(t *testing.T) {
	b := &bundle.Bundle{}
	o := Old{Scheme: "https", Host: "h", Path: "/sub"}
	same := o
	same.Port = 443 // the scheme's default, spelled out
	Add(b, []Old{o, same, {Scheme: "https", Host: "h", Path: "/json", Format: "xray"}})
	if len(b.Items) != 2 {
		t.Fatalf("%d items, want 2", len(b.Items))
	}
}

// panel is a connected client to a fake NX with the given ingress.
func panel(t *testing.T, ing *targettest.Ingress, subURL string) *target.Client {
	t.Helper()
	mux := http.NewServeMux()
	ok := func(v any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	mux.HandleFunc("POST /api/login", ok(map[string]any{"token": "t"}))
	mux.HandleFunc("GET /api/me", ok(map[string]any{"username": "sudo", "role": "sudo", "base": "sudo"}))
	mux.HandleFunc("GET /api/users", ok([]map[string]any{{"name": "ali", "subUrl": subURL}}))
	ing.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c, err := target.Connect(context.Background(), target.Options{BaseURL: ts.URL, Username: "sudo", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func items(olds ...Old) []bundle.Item {
	out := make([]bundle.Item, 0, len(olds))
	for _, o := range olds {
		out = append(out, o.Item())
	}
	return out
}

// The 3x-ui case the whole feature is for: a random path on port 2096 is
// added in front of NX's own routes as a redirect to NX's /sub, keeping the
// rest of the path; the JSON path also names its format. NX's own routes are
// all still there, in their order, after the new ones.
func TestApplyAddsRedirectsInFront(t *testing.T) {
	ing := targettest.New()
	c := panel(t, ing, "https://sub.nx.test/sub/ali-token")
	links := items(
		Old{Scheme: "https", Host: "sub.old.com", Port: 2096, Path: "/k3j9x0q2"},
		Old{Scheme: "https", Host: "sub.old.com", Port: 2096, Path: "/p0q9json", Format: "xray"},
	)
	out := Apply(context.Background(), c, links)
	for _, o := range out {
		if o.Status != created {
			t.Fatalf("%s: %s — %s", o.Item.Name, o.Status, o.Message)
		}
	}
	if ing.Puts != 1 || ing.Confirms != 1 {
		t.Fatalf("puts = %d, confirms = %d; want one confirmed change", ing.Puts, ing.Confirms)
	}
	if len(ing.Routes) != 3 || ing.Routes[2]["name"] != "panel" {
		t.Fatalf("routes = %v; want the two redirects, then NX's panel route", ing.Routes)
	}
	r := ing.Route("old-sub-sub-old-com-2096-k3j9x0q2")
	if r == nil {
		t.Fatal("the links route is missing")
	}
	reply := r["reply"].(map[string]any)
	if r["service"] != "redirect" || r["prefix"] != "/k3j9x0q2" || reply["to"] != "https://sub.nx.test/sub" ||
		reply["keepPath"] != true || reply["code"] != float64(302) {
		t.Errorf("route = %v", r)
	}
	if hosts := r["hosts"].([]any); len(hosts) != 1 || hosts[0] != "sub.old.com" {
		t.Errorf("hosts = %v", hosts)
	}
	// No listener is bound to 2096, so the route is on every one, and the
	// outcome says why.
	if !strings.Contains(out[0].Message, "port 2096") {
		t.Errorf("message = %q", out[0].Message)
	}
	j := ing.Route("old-sub-sub-old-com-2096-p0q9json-xray")
	if j == nil || j["reply"].(map[string]any)["to"] != "https://sub.nx.test/sub?format=xray" {
		t.Errorf("json route = %v", j)
	}

	// A second run finds its own routes and changes nothing.
	again := Apply(context.Background(), c, links)
	for _, o := range again {
		if o.Status != exists {
			t.Errorf("second run: %s %s — %s", o.Item.Name, o.Status, o.Message)
		}
	}
	if ing.Puts != 1 {
		t.Errorf("a second run changed the ingress again")
	}
}

// Marzban's default /sub/ on a host NX already answers needs nothing.
func TestApplyLeavesWhatAlreadyWorks(t *testing.T) {
	ing := targettest.New()
	ing.Routes = append([]map[string]any{{"name": "subscriptions", "listeners": []any{"main"},
		"hosts": []any{}, "prefix": "", "service": "sub"}}, ing.Routes...)
	c := panel(t, ing, "https://sub.nx.test/sub/ali-token")
	out := Apply(context.Background(), c, items(Old{Scheme: "https", Host: "sub.old.com", Path: "/sub"}))
	if out[0].Status != exists || ing.Puts != 0 {
		t.Fatalf("%s — %s (puts %d)", out[0].Status, out[0].Message, ing.Puts)
	}
}

// A hostless /sub/ on a panel whose own /sub/ is host-limited must not take
// NX's own subscription address: it excludes that host, and the draft test
// proves the canonical address still reaches NX's route.
func TestApplyHostlessExcludesNXsOwnHost(t *testing.T) {
	ing := targettest.New()
	ing.Routes[0]["panel"] = map[string]any{"sub": false}
	ing.Routes = append([]map[string]any{{"name": "subscriptions", "listeners": []any{"main"},
		"hosts": []any{"sub.nx.test"}, "prefix": "", "service": "sub"}}, ing.Routes...)
	c := panel(t, ing, "https://sub.nx.test/sub/ali-token")
	out := Apply(context.Background(), c, items(Old{Scheme: "http", Port: 2096, Path: "/sub"}))
	if out[0].Status != created {
		t.Fatalf("%s — %s", out[0].Status, out[0].Message)
	}
	r := ing.Route("old-sub-any-host-2096-sub")
	if ex := r["excludeHosts"].([]any); len(ex) != 1 || ex[0] != "sub.nx.test" {
		t.Errorf("excludeHosts = %v", r["excludeHosts"])
	}
}

// An old path NX itself uses is refused rather than covered.
func TestApplyRefusesNXsOwnPaths(t *testing.T) {
	ing := targettest.New()
	c := panel(t, ing, "https://nx.test/sub/ali-token")
	out := Apply(context.Background(), c, items(Old{Scheme: "https", Host: "nx.test", Path: "/api"}))
	if out[0].Status != failed || !strings.Contains(out[0].Message, "panel") || ing.Puts != 0 {
		t.Fatalf("%s — %s (puts %d)", out[0].Status, out[0].Message, ing.Puts)
	}
}

func TestApplyWaitsForNobodyElsesChange(t *testing.T) {
	ing := targettest.New()
	ing.PendingOther = true
	c := panel(t, ing, "https://sub.nx.test/sub/ali-token")
	out := Apply(context.Background(), c, items(Old{Scheme: "https", Host: "sub.old.com", Path: "/x"}))
	if out[0].Status != failed || !strings.Contains(out[0].Message, "waiting") || ing.Puts != 0 {
		t.Fatalf("%s — %s", out[0].Status, out[0].Message)
	}
}

// NX building its links on the address this tool reached it by is a panel
// with no public address; redirecting customers there would send them to
// 127.0.0.1.
func TestApplyRefusesALoopbackSubscriptionAddress(t *testing.T) {
	ing := targettest.New()
	c := panel(t, ing, "http://127.0.0.1:8080/sub/ali-token")
	out := Apply(context.Background(), c, items(Old{Scheme: "https", Host: "sub.old.com", Path: "/x"}))
	if out[0].Status != failed || !strings.Contains(out[0].Message, "public") || ing.Puts != 0 {
		t.Fatalf("%s — %s", out[0].Status, out[0].Message)
	}
}
