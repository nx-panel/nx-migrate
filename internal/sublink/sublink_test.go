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
		got, ok := fromURL(c.in, "", "")
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("fromURL(%q) = %+v, %v; want %+v, %v", c.in, got, ok, c.want, c.ok)
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
	if got := o.RouteName(); !strings.HasPrefix(got, "old-sub-sub-old-com-2096-k3j9x0q2-xray-") || len(got) != len("old-sub-sub-old-com-2096-k3j9x0q2-xray-")+8 {
		t.Errorf("RouteName = %q", got)
	}
	hostless := Old{Scheme: "http", Port: 2096, Path: "/sub"}
	if got := hostless.Example(); got != "http://{server}:2096/sub/{token}" {
		t.Errorf("hostless Example = %q", got)
	}
	if got := hostless.RouteName(); !strings.HasPrefix(got, "old-sub-any-host-2096-sub-") {
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
	return panelWith(t, ing, []map[string]any{{"name": "ali", "subUrl": subURL}})
}

// panelWith is a connected client whose account list is rows.
func panelWith(t *testing.T, ing *targettest.Ingress, rows []map[string]any) *target.Client {
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
	mux.HandleFunc("GET /api/users", ok(rows))
	ing.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c, err := target.Connect(context.Background(), target.Options{BaseURL: ts.URL, Username: "sudo", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustDecode(t *testing.T, it bundle.Item) Old {
	t.Helper()
	o, err := Decode(it)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func links0(t *testing.T, its []bundle.Item) Old { return mustDecode(t, its[0]) }

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
		if o.Status != Created {
			t.Fatalf("%s: %s — %s", o.Item.Name, o.Status, o.Message)
		}
	}
	if ing.Puts != 1 || ing.Confirms != 1 {
		t.Fatalf("puts = %d, confirms = %d; want one confirmed change", ing.Puts, ing.Confirms)
	}
	if len(ing.Routes) != 3 || ing.Routes[2]["name"] != "panel" {
		t.Fatalf("routes = %v; want the two redirects, then NX's panel route", ing.Routes)
	}
	r := ing.Route(links0(t, links).RouteName())
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
	j := ing.Route(mustDecode(t, links[1]).RouteName())
	if j == nil || j["reply"].(map[string]any)["to"] != "https://sub.nx.test/sub?format=xray" {
		t.Errorf("json route = %v", j)
	}

	// A second run finds its own routes and changes nothing.
	again := Apply(context.Background(), c, links)
	for _, o := range again {
		if o.Status != Exists {
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
	if out[0].Status != Exists || ing.Puts != 0 {
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
	if out[0].Status != Created {
		t.Fatalf("%s — %s", out[0].Status, out[0].Message)
	}
	r := ing.Route(Old{Scheme: "http", Port: 2096, Path: "/sub"}.RouteName())
	if ex := r["excludeHosts"].([]any); len(ex) != 1 || ex[0] != "sub.nx.test" {
		t.Errorf("excludeHosts = %v", r["excludeHosts"])
	}
}

// An old path NX itself uses is refused rather than covered.
func TestApplyRefusesNXsOwnPaths(t *testing.T) {
	ing := targettest.New()
	c := panel(t, ing, "https://nx.test/sub/ali-token")
	out := Apply(context.Background(), c, items(Old{Scheme: "https", Host: "nx.test", Path: "/api"}))
	if out[0].Status != Failed || !strings.Contains(out[0].Message, "panel") || ing.Puts != 0 {
		t.Fatalf("%s — %s (puts %d)", out[0].Status, out[0].Message, ing.Puts)
	}
}

func TestApplyWaitsForNobodyElsesChange(t *testing.T) {
	ing := targettest.New()
	ing.PendingOther = true
	c := panel(t, ing, "https://sub.nx.test/sub/ali-token")
	out := Apply(context.Background(), c, items(Old{Scheme: "https", Host: "sub.old.com", Path: "/x"}))
	if out[0].Status != Failed || !strings.Contains(out[0].Message, "waiting") || ing.Puts != 0 {
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
	if out[0].Status != Failed || !strings.Contains(out[0].Message, "public") || ing.Puts != 0 {
		t.Fatalf("%s — %s", out[0].Status, out[0].Message)
	}
}

// NX mounts /sub/{token} only: an old path under /sub, such as s-ui's
// /sub/vpn/, is not one NX answers, so it is redirected rather than reported
// as already working.
func TestApplyRedirectsANestedSubPath(t *testing.T) {
	ing := targettest.New()
	c := panel(t, ing, "https://sub.nx.test/sub/ali-token")
	o := Old{Scheme: "https", Host: "sub.old.com", Path: "/sub/vpn"}
	out := Apply(context.Background(), c, items(o))
	if out[0].Status != Created || ing.Route(o.RouteName()) == nil {
		t.Fatalf("%s — %s", out[0].Status, out[0].Message)
	}
}

// A hostless redirect takes no host a route of NX's names, so a reseller's
// domain and the other subscription names keep their own routes.
func TestApplyHostlessExcludesEveryNamedHost(t *testing.T) {
	ing := targettest.New()
	ing.Routes[0]["panel"] = map[string]any{"sub": false}
	ing.Routes = append([]map[string]any{
		{"name": "subscriptions", "listeners": []any{"main"}, "hosts": []any{"sub.nx.test"}, "prefix": "", "service": "sub"},
		{"name": "reseller", "listeners": []any{"main"}, "hosts": []any{"shop.example.com"}, "prefix": "", "service": "sub", "adminId": 7, "canonical": true},
		{"name": "fronts", "listeners": []any{"main"}, "hosts": []any{"*.cdn.nx.test"}, "prefix": "", "service": "sub"},
	}, ing.Routes...)
	c := panel(t, ing, "https://sub.nx.test/sub/ali-token")
	o := Old{Scheme: "http", Port: 2096, Path: "/sub"}
	out := Apply(context.Background(), c, items(o))
	if out[0].Status != Created {
		t.Fatalf("%s — %s", out[0].Status, out[0].Message)
	}
	got := strings.Join(targettestStrs(ing.Route(o.RouteName())["excludeHosts"]), ",")
	if got != "sub.nx.test,shop.example.com,*.cdn.nx.test" {
		t.Errorf("excludeHosts = %s", got)
	}
}

func targettestStrs(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, e.(string))
	}
	return out
}

// An address NX already answers, but on a port nothing of NX's listens on,
// says so instead of claiming the link works.
func TestApplyExistsSaysThePort(t *testing.T) {
	ing := targettest.New()
	c := panel(t, ing, "https://sub.nx.test/sub/ali-token")
	out := Apply(context.Background(), c, items(Old{Scheme: "https", Host: "sub.old.com", Port: 2096, Path: "/sub"}))
	if out[0].Status != Exists || !strings.Contains(out[0].Message, "port 2096") || ing.Puts != 0 {
		t.Fatalf("%s — %s (puts %d)", out[0].Status, out[0].Message, ing.Puts)
	}
}

// The panel's warnings on the saved change reach the outcome; a change that
// would take something of NX's is not confirmed.
func TestApplyReadsThePanelsWarnings(t *testing.T) {
	o := Old{Scheme: "https", Host: "sub.old.com", Path: "/k3j9x0q2"}
	ing := targettest.New()
	ing.Warnings = []map[string]any{{"kind": "listener", "name": "main", "code": "certificate", "other": o.RouteName(), "detail": "sub.old.com"}}
	ing.Restart = true
	c := panel(t, ing, "https://sub.nx.test/sub/ali-token")
	out := Apply(context.Background(), c, items(o))
	if out[0].Status != Created || !strings.Contains(out[0].Message, "no certificate for sub.old.com") ||
		!strings.Contains(out[0].Message, "restarted") {
		t.Fatalf("%s — %s", out[0].Status, out[0].Message)
	}

	ing = targettest.New()
	ing.Warnings = []map[string]any{{"kind": "route", "name": "panel", "code": "shadowed", "other": o.RouteName(), "detail": "sub.old.com/k3j9x0q2"}}
	c = panel(t, ing, "https://sub.nx.test/sub/ali-token")
	out = Apply(context.Background(), c, items(o))
	if out[0].Status != Failed || ing.Confirms != 0 || !strings.Contains(out[0].Message, "not confirmed") {
		t.Fatalf("%s — %s (confirms %d)", out[0].Status, out[0].Message, ing.Confirms)
	}
}

// A TLS listener that refuses names it holds no certificate for refuses the
// old name too: the route would never be reached, so it is not added.
func TestApplyRefusedHandshake(t *testing.T) {
	ing := targettest.New()
	ing.Listeners[0]["state"] = map[string]any{"address": "0.0.0.0:443", "tls": true}
	ing.NoCert = map[string]bool{"sub.old.com": true}
	c := panel(t, ing, "https://sub.nx.test/sub/ali-token")
	out := Apply(context.Background(), c, items(Old{Scheme: "https", Host: "sub.old.com", Path: "/k3j9x0q2"}))
	if out[0].Status != Failed || !strings.Contains(out[0].Message, "certificate") || ing.Puts != 0 {
		t.Fatalf("%s — %s (puts %d)", out[0].Status, out[0].Message, ing.Puts)
	}
}

// The redirect goes to NX's shared address: an account on a reseller's own
// subscription route is passed over, and a wildcard that mints a name per
// subscriber is refused.
func TestApplyTargetIsTheSharedAddress(t *testing.T) {
	ing := targettest.New()
	ing.Routes = append([]map[string]any{{"name": "reseller", "listeners": []any{"main"}, "hosts": []any{"shop.example.com"},
		"prefix": "", "service": "sub", "adminId": 7, "canonical": true}}, ing.Routes...)
	c := panelWith(t, ing, []map[string]any{
		{"name": "theirs", "adminId": 7, "subUrl": "https://shop.example.com/sub/a"},
		{"name": "ours", "adminId": 1, "subUrl": "https://sub.nx.test/sub/b"},
	})
	o := Old{Scheme: "https", Host: "sub.old.com", Path: "/k3j9x0q2"}
	out := Apply(context.Background(), c, items(o))
	if out[0].Status != Created {
		t.Fatalf("%s — %s", out[0].Status, out[0].Message)
	}
	if to := ing.Route(o.RouteName())["reply"].(map[string]any)["to"]; to != "https://sub.nx.test/sub" {
		t.Errorf("to = %v", to)
	}

	ing = targettest.New()
	ing.Routes = append([]map[string]any{{"name": "fronts", "listeners": []any{"main"}, "hosts": []any{"*.sub.nx.test"},
		"prefix": "", "service": "sub"}}, ing.Routes...)
	c = panel(t, ing, "https://nx-sub-ab12cd.sub.nx.test/sub/b")
	out = Apply(context.Background(), c, items(o))
	if out[0].Status != Failed || !strings.Contains(out[0].Message, "*.sub.nx.test") || ing.Puts != 0 {
		t.Fatalf("%s — %s", out[0].Status, out[0].Message)
	}
}

// Addresses that spell alike, or that a long host cuts short, keep names of
// their own.
func TestRouteNamesAreDistinct(t *testing.T) {
	long := strings.Repeat("a", 55) + ".example"
	pairs := [][2]Old{
		{{Host: "a.b", Path: "/sub.v2"}, {Host: "a.b", Path: "/sub-v2"}},
		{{Host: long, Port: 2096, Path: "/sub"}, {Host: long, Port: 2096, Path: "/json", Format: "xray"}},
	}
	for _, p := range pairs {
		a, b := p[0].RouteName(), p[1].RouteName()
		if a == b || len(a) > 64 || len(b) > 64 {
			t.Errorf("%q and %q", a, b)
		}
	}
}

func TestSettingsOld(t *testing.T) {
	bad := Settings{"subPort": "abc"}
	if _, err := bad.Address("subURI", "subPath", "/sub/", "x", ""); err == nil {
		t.Error("a port that is not a number was taken")
	}
	for _, d := range []string{"sub.old.com/", "https://sub.old.com", "sub.old.com:2096", "a b.com"} {
		if o, err := (Settings{"subDomain": d}).Address("subURI", "subPath", "/sub/", "x", ""); err == nil {
			t.Errorf("subDomain %q was taken as %+v", d, o)
		}
	}
	if _, err := (Settings{"subURI": "ftp://x/"}).Address("subURI", "subPath", "/sub/", "x", ""); err == nil {
		t.Error("an unusable subURI fell back to the domain")
	}
	idn, err := (Settings{"subDomain": "Пример.РФ."}).Address("subURI", "subPath", "/sub/", "x", "")
	if err != nil || idn.Host != "xn--e1afmkfd.xn--p1ai" {
		t.Errorf("an internationalised domain = %+v, %v", idn, err)
	}
	good := Settings{"subDomain": "Sub.Old.com"}
	o, err := good.Address("subURI", "subPath", "/sub/", "x", "")
	if err != nil || o.Port != defaultSubPort || o.Scheme != "http" || o.Base() != "http://sub.old.com:2096/sub/" {
		t.Errorf("defaults = %+v, base %q", o, o.Base())
	}
}

// NX on the old server's own IP, no domains: the hostless redirect must not
// exclude that IP, which is the very host the old links name.
func TestApplyHostlessOnNXsOwnIP(t *testing.T) {
	ing := targettest.New()
	c := panel(t, ing, "http://203.0.113.7:2095/sub/ali-token")
	o := Old{Scheme: "http", Port: 2096, Path: "/k3j9x0q2"}
	out := Apply(context.Background(), c, items(o))
	if out[0].Status != Created {
		t.Fatalf("%s — %s", out[0].Status, out[0].Message)
	}
	if ex, ok := ing.Route(o.RouteName())["excludeHosts"]; ok {
		t.Errorf("excludeHosts = %v, want none", ex)
	}
	a, err := c.TestRoute(context.Background(), target.RouteTest{Listener: "main", Host: "203.0.113.7:2096", Path: "/k3j9x0q2/abc"})
	if err != nil || a.Route != o.RouteName() {
		t.Errorf("a customer's request = %+v, %v", a, err)
	}
}

func TestApplyChangeOutcomes(t *testing.T) {
	o := Old{Scheme: "https", Host: "sub.old.com", Path: "/k3j9x0q2"}

	// A stale second factor.
	ing := targettest.New()
	ing.PutStatus = http.StatusPreconditionRequired
	out := Apply(context.Background(), panel(t, ing, "https://sub.nx.test/sub/a"), items(o))
	if out[0].Status != Failed || !strings.Contains(out[0].Message, "authenticator code") {
		t.Errorf("428: %s — %s", out[0].Status, out[0].Message)
	}

	// A confirmation asked again while the change is still being applied.
	ing = targettest.New()
	ing.Busy = 2
	out = Apply(context.Background(), panel(t, ing, "https://sub.nx.test/sub/a"), items(o))
	if out[0].Status != Created || ing.Confirms != 1 {
		t.Errorf("busy: %s — %s (confirms %d)", out[0].Status, out[0].Message, ing.Confirms)
	}

	// Stopped while the change is being saved: no token came back, so it is
	// not confirmed and goes back.
	ing = targettest.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ing.OnPut = cancel
	out = Apply(ctx, panel(t, ing, "https://sub.nx.test/sub/a"), items(o))
	if out[0].Status != Skipped || ing.Confirms != 0 || !strings.Contains(out[0].Message, "puts it back") {
		t.Errorf("cancelled during the change: %s — %s (confirms %d)", out[0].Status, out[0].Message, ing.Confirms)
	}

	// Stopped during the confirmation: it is confirmed all the same, so
	// what is reported is what the panel holds.
	ing = targettest.New()
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	ing.Busy = 1
	ing.OnConfirm = cancel
	out = Apply(ctx, panel(t, ing, "https://sub.nx.test/sub/a"), items(o))
	if out[0].Status != Created || ing.Confirms != 1 {
		t.Errorf("cancelled during the confirmation: %s — %s (confirms %d)", out[0].Status, out[0].Message, ing.Confirms)
	}

	// Another admin changed the table while the run was testing.
	ing = targettest.New()
	once := false
	ing.OnTest = func() {
		if !once {
			once = true
			ing.Edit(func(r []map[string]any) []map[string]any {
				return append(r, map[string]any{"name": "shop", "listeners": []any{"main"}, "hosts": []any{"shop.example.com"}, "service": "static"})
			})
		}
	}
	out = Apply(context.Background(), panel(t, ing, "https://sub.nx.test/sub/a"), items(o))
	if out[0].Status != Failed || ing.Puts != 0 || !strings.Contains(out[0].Message, "changed while") {
		t.Errorf("changed meanwhile: %s — %s (puts %d)", out[0].Status, out[0].Message, ing.Puts)
	}
}

// What the listeners say reaches the outcome: a listener on the old port
// that serves the wrong scheme, or one that did not come up.
func TestApplyListenerNotes(t *testing.T) {
	ing := targettest.New()
	ing.Listeners = append(ing.Listeners, map[string]any{"name": "alt", "listenPort": "2096", "state": map[string]any{"address": "0.0.0.0:2096", "tls": false}})
	ing.Routes[0]["listeners"] = []any{"main", "alt"}
	c := panel(t, ing, "https://sub.nx.test/sub/a")
	out := Apply(context.Background(), c, items(Old{Scheme: "https", Host: "sub.old.com", Port: 2096, Path: "/k3j9x0q2"}))
	if out[0].Status != Created || !strings.Contains(out[0].Message, "plain HTTP") {
		t.Errorf("scheme: %s — %s", out[0].Status, out[0].Message)
	}

	ing = targettest.New()
	ing.Listeners = append(ing.Listeners, map[string]any{"name": "alt", "listenPort": "2096", "state": map[string]any{"address": "0.0.0.0:2096", "error": "address already in use"}})
	c = panel(t, ing, "https://sub.nx.test/sub/a")
	o := Old{Scheme: "https", Host: "sub.old.com", Port: 2096, Path: "/p0q9"}
	out = Apply(context.Background(), c, items(o))
	if out[0].Status != Created || !strings.Contains(out[0].Message, "did not come up") {
		t.Errorf("failed listener: %s — %s", out[0].Status, out[0].Message)
	}
	if l := targettestStrs(ing.Route(o.RouteName())["listeners"]); len(l) != 1 || l[0] != "main" {
		t.Errorf("listeners = %v, want only the one serving", l)
	}
}

// A catch-all decoy page answers every path; taking an old path from it is
// not taking anything NX serves.
func TestApplyTakesFromADecoy(t *testing.T) {
	ing := targettest.New()
	ing.Routes = []map[string]any{
		{"name": "panel", "listeners": []any{"main"}, "hosts": []any{"nx.test"}, "prefix": "", "service": "panel"},
		{"name": "decoy", "listeners": []any{"main"}, "hosts": []any{}, "prefix": "", "service": "static"},
	}
	c := panel(t, ing, "https://nx.test/sub/a")
	out := Apply(context.Background(), c, items(Old{Scheme: "https", Host: "sub.old.com", Path: "/k3j9x0q2"}))
	if out[0].Status != Created {
		t.Errorf("%s — %s", out[0].Status, out[0].Message)
	}
}

// Stopped while the addresses are being tested: every item still ends with
// an outcome, those already planned included, and nothing is saved.
func TestApplyStoppedMidTestsSkipsEveryRemainingItem(t *testing.T) {
	for _, stopAt := range []int{2, 3, 4, 5} {
		ing := targettest.New()
		ctx, cancel := context.WithCancel(context.Background())
		n := 0
		ing.OnTest = func() {
			if n++; n == stopAt {
				cancel()
			}
		}
		c := panel(t, ing, "https://sub.nx.test/sub/a")
		out := Apply(ctx, c, items(
			Old{Scheme: "https", Host: "a.old.com", Path: "/p1"},
			Old{Scheme: "https", Host: "b.old.com", Path: "/p2"},
		))
		cancel()
		if len(out) != 2 || ing.Puts != 0 {
			t.Fatalf("stop at test %d: %d outcomes, %d puts: %+v", stopAt, len(out), ing.Puts, out)
		}
		for _, o := range out {
			if o.Status != Skipped {
				t.Errorf("stop at test %d: %s %s — %s", stopAt, o.Item.Name, o.Status, o.Message)
			}
		}
	}
}

func TestNormalHost(t *testing.T) {
	cases := map[string]string{
		"Sub.Old.com.":                "sub.old.com",
		"my_sub.example.com":          "my_sub.example.com",
		"r3---sn-abc.googlevideo.com": "r3---sn-abc.googlevideo.com",
		"пример.рф":                   "xn--e1afmkfd.xn--p1ai",
		"2001:0db8::0001":             "2001:0db8::0001",
		"[2001:db8::1]":               "2001:db8::1",
		"203.0.113.7":                 "203.0.113.7",
	}
	for in, want := range cases {
		if got, err := normalHost(in); err != nil || got != want {
			t.Errorf("normalHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "sub.old.com/", "https://sub.old.com", "sub.old.com:2096", "a b.com", "a..b"} {
		if got, err := normalHost(bad); err == nil {
			t.Errorf("normalHost(%q) = %q, want an error", bad, got)
		}
	}
}

// An old IPv6 host goes through to the panel as written.
func TestApplyIPv6Host(t *testing.T) {
	ing := targettest.New()
	c := panel(t, ing, "https://sub.nx.test/sub/a")
	o, ok := fromURL("http://[2001:db8::1]:2096/k3j9x0q2/", "subscription", "")
	if !ok {
		t.Fatal("not read")
	}
	out := Apply(context.Background(), c, items(o))
	if out[0].Status != Created {
		t.Fatalf("%s — %s", out[0].Status, out[0].Message)
	}
	if !strings.Contains(out[0].Message, "http://[2001:db8::1]:2096/k3j9x0q2/{token}") {
		t.Errorf("message = %s", out[0].Message)
	}
}

// https old links sent to an http NX address say so.
func TestApplySaysADowngrade(t *testing.T) {
	ing := targettest.New()
	c := panel(t, ing, "http://sub.nx.test/sub/a")
	out := Apply(context.Background(), c, items(Old{Scheme: "https", Host: "sub.old.com", Path: "/k3j9x0q2"}))
	if out[0].Status != Created || !strings.Contains(out[0].Message, "plain http") {
		t.Errorf("%s — %s", out[0].Status, out[0].Message)
	}
}

// An old path that is one of NX's own pages is not taken from it.
func TestApplyRefusesNXsPages(t *testing.T) {
	ing := targettest.New()
	c := panel(t, ing, "https://sub.nx.test/sub/a")
	out := Apply(context.Background(), c, items(Old{Scheme: "http", Port: 2096, Path: "/login"}))
	if out[0].Status != Failed || ing.Puts != 0 {
		t.Errorf("%s — %s (puts %d)", out[0].Status, out[0].Message, ing.Puts)
	}
}
