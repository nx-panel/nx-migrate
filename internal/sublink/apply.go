package sublink

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/nx-panel/nx-migrate/internal/bundle"
	"github.com/nx-panel/nx-migrate/internal/target"
)

// Outcome is how one address ended.
type Outcome struct {
	Item bundle.Item
	// Status is "created", "exists" or "failed", the applier's words.
	Status  string
	Message string
}

const (
	created = "created"
	exists  = "exists"
	failed  = "failed"
)

// probe stands in for a token in the route tests: any value under the path
// is routed the same way.
const probe = "nx-migrate-probe"

// probeHost stands in for "any host" when the old panel had no domain.
const probeHost = "old-panel.invalid"

// Apply adds a redirect route for every address that NX does not already
// answer, in one change to the ingress, and confirms it. Every item ends with
// an outcome.
func Apply(ctx context.Context, c *target.Client, items []bundle.Item) []Outcome {
	out := apply(ctx, c, items)
	// In the order they were given, which is the order the operator saw.
	at := make(map[string]int, len(items))
	for i, it := range items {
		at[it.ID] = i
	}
	sort.SliceStable(out, func(i, j int) bool { return at[out[i].Item.ID] < at[out[j].Item.ID] })
	return out
}

func apply(ctx context.Context, c *target.Client, items []bundle.Item) []Outcome {
	out := make([]Outcome, 0, len(items))
	failAll := func(format string, args ...any) []Outcome {
		msg := fmt.Sprintf(format, args...)
		for _, it := range items {
			out = append(out, Outcome{Item: it, Status: failed, Message: msg})
		}
		return out
	}

	base, err := c.SubscriptionBase(ctx)
	if err != nil {
		return failAll("NX's own subscription address could not be read, so there is nothing to send the old links to: %v", err)
	}
	baseURL, _ := url.Parse(base)
	in, err := c.Ingress(ctx)
	if err != nil {
		return failAll("NX's addresses could not be read: %v", err)
	}
	if in.Pending {
		return failAll("another change to NX's addresses is waiting for its confirmation; confirm it or let it be put back, then run the transfer again with these ticked")
	}
	names := in.RouteNames()

	type planned struct {
		item      bundle.Item
		old       Old
		route     map[string]any
		listeners []string
		note      string
	}
	var plan []planned
	for _, it := range items {
		o, err := Decode(it)
		if err != nil {
			out = append(out, Outcome{Item: it, Status: failed, Message: err.Error()})
			continue
		}
		if problem := PrefixProblem(o.Path); problem != "" {
			out = append(out, Outcome{Item: it, Status: failed, Message: problem})
			continue
		}
		name := o.RouteName()
		if names[name] {
			out = append(out, Outcome{Item: it, Status: exists,
				Message: fmt.Sprintf("NX already has the route %q for this address, so it was left alone", name)})
			continue
		}
		listeners, note := listenersFor(in.Listeners, o.EffectivePort())
		if len(listeners) == 0 {
			out = append(out, Outcome{Item: it, Status: failed, Message: "NX has no listener switched on to put the route on"})
			continue
		}
		works, clash, err := current(ctx, c, o, listeners)
		if err != nil {
			out = append(out, Outcome{Item: it, Status: failed, Message: "NX's route test could not be asked: " + err.Error()})
			continue
		}
		if clash != "" {
			out = append(out, Outcome{Item: it, Status: failed, Message: clash})
			continue
		}
		if works {
			out = append(out, Outcome{Item: it, Status: exists,
				Message: "NX already answers this address with its subscriptions, so there was nothing to add"})
			continue
		}
		names[name] = true
		plan = append(plan, planned{item: it, old: o, route: route(o, name, listeners, base, baseURL.Hostname()),
			listeners: listeners, note: note})
	}
	if len(plan) == 0 {
		return out
	}

	routes := make([]any, 0, len(plan))
	for _, p := range plan {
		routes = append(routes, p.route)
	}
	draft, err := in.WithRoutes(routes)
	if err != nil {
		for _, p := range plan {
			out = append(out, Outcome{Item: p.item, Status: failed, Message: err.Error()})
		}
		return out
	}

	// Ask the panel about the draft before saving it: each old link must
	// meet its own redirect, and NX's own subscription address must not meet
	// any of them — that would be a redirect to itself.
	var keep []planned
	for _, p := range plan {
		if msg := verify(ctx, c, draft, p.old, p.route["name"].(string), p.listeners, baseURL); msg != "" {
			out = append(out, Outcome{Item: p.item, Status: failed, Message: msg})
			continue
		}
		keep = append(keep, p)
	}
	if len(keep) == 0 {
		return out
	}
	if len(keep) != len(plan) {
		routes = routes[:0]
		for _, p := range keep {
			routes = append(routes, p.route)
		}
		draft, _ = in.WithRoutes(routes)
	}

	token, err := c.ReplaceIngress(ctx, draft)
	if err == nil {
		err = c.ConfirmIngress(ctx, token)
		if err != nil {
			err = fmt.Errorf("NX saved the routes but the change could not be confirmed (%v), so the panel puts it back by itself within two minutes", err)
		}
	} else if target.IsConfirmRequired(err) {
		err = fmt.Errorf("NX wants a fresh authenticator code before it changes its addresses: run the transfer again with these ticked and a new code")
	}
	for _, p := range keep {
		if err != nil {
			out = append(out, Outcome{Item: p.item, Status: failed, Message: err.Error()})
			continue
		}
		msg := fmt.Sprintf("added the route %q: %s now redirects to %s", p.route["name"], p.old.Example(),
			redirectExample(p.route))
		if p.note != "" {
			msg += "; " + p.note
		}
		out = append(out, Outcome{Item: p.item, Status: created, Message: msg})
	}
	return out
}

// listenersFor are the listeners an old link can arrive on: those bound to
// its port, or — when none is, or the port is not known — every listener that
// is on, since a proxy in front of NX may bring that port to any of them.
func listenersFor(all []target.IngressListener, port int) ([]string, string) {
	var on, matching []string
	for _, l := range all {
		if !l.On() {
			continue
		}
		on = append(on, l.Name)
		if port != 0 && portOf(l.Address()) == port {
			matching = append(matching, l.Name)
		}
	}
	if len(matching) > 0 {
		return matching, ""
	}
	if port != 0 {
		return on, fmt.Sprintf("no NX listener is bound to port %d, so the route is on every listener: it answers once that port reaches NX, through a listener on it or a proxy in front", port)
	}
	return on, ""
}

// current asks the saved table about the old link. works is set when NX
// already answers it with its subscriptions on every listener it can arrive
// on; clash names a route of NX's that the old path would be taken from.
func current(ctx context.Context, c *target.Client, o Old, listeners []string) (works bool, clash string, err error) {
	works = true
	for _, l := range listeners {
		a, err := c.TestRoute(ctx, target.RouteTest{Listener: l, Host: testHost(o), Path: o.Path + "/" + probe})
		if err != nil {
			return false, "", err
		}
		if a.Outcome == "route" && servesSub(a) && o.Format == "" {
			continue
		}
		works = false
		if a.Outcome == "route" && takenFromNX(a) {
			return false, fmt.Sprintf("NX's route %q already answers %s (%s), and a redirect in front of it would take that away", a.Route, o.Path, a.Service), nil
		}
	}
	return works, "", nil
}

// servesSub reports whether an answer is NX's subscription service.
func servesSub(a target.RouteAnswer) bool {
	return (a.Service == "sub" || a.Service == "panel") && (a.Path == "/sub" || strings.HasPrefix(a.Path, "/sub/"))
}

// takenFromNX reports whether an answer is something of NX's own that a
// redirect must not cover. The panel's single-page app answers every path it
// does not know, so a panel route counts only for the paths it really serves.
func takenFromNX(a target.RouteAnswer) bool {
	switch a.Service {
	case "panel":
		for _, p := range []string{"/api", "/sub", "/install", "/metrics", "/assets"} {
			if a.Path == p || strings.HasPrefix(a.Path, p+"/") {
				return true
			}
		}
		return a.Path == "/install-node.sh"
	case "":
		return false
	}
	return true
}

func testHost(o Old) string {
	if o.Host == "" {
		return probeHost
	}
	return o.Host
}

// route is the route document for an old address.
func route(o Old, name string, listeners []string, base, baseHost string) map[string]any {
	to := base
	if o.Format != "" {
		to += "?format=" + url.QueryEscape(o.Format)
	}
	r := map[string]any{
		"name":      name,
		"listeners": listeners,
		"hosts":     []string{},
		"prefix":    o.Path,
		"service":   "redirect",
		// 302, not 301: a permanent redirect is kept by clients for good,
		// and this one is meant to be removable.
		"reply": map[string]any{"to": to, "code": 302, "keepPath": true},
	}
	if o.Host != "" {
		r["hosts"] = []string{o.Host}
	} else if baseHost != "" {
		r["excludeHosts"] = []string{baseHost}
	}
	return r
}

func redirectExample(r map[string]any) string {
	reply, _ := r["reply"].(map[string]any)
	to, _ := reply["to"].(string)
	u, err := url.Parse(to)
	if err != nil {
		return to
	}
	u.Path += "/{token}"
	s := u.String()
	return strings.Replace(s, "%7Btoken%7D", "{token}", 1)
}

// verify asks the panel about the draft. "" is good.
func verify(ctx context.Context, c *target.Client, draft any, o Old, name string, listeners []string, base *url.URL) string {
	for _, l := range listeners {
		a, err := c.TestRoute(ctx, target.RouteTest{Listener: l, Host: testHost(o), Path: o.Path + "/" + probe, Ingress: draft})
		if err != nil {
			return "NX refused the route: " + err.Error()
		}
		if a.Outcome != "route" || !strings.EqualFold(a.Route, name) {
			got := a.Route
			if got == "" {
				got = a.Outcome
			}
			return fmt.Sprintf("NX would not send the old link to its new route but to %q; add the redirect by hand", got)
		}
		own, err := c.TestRoute(ctx, target.RouteTest{Listener: l, Host: base.Hostname(), Path: base.Path + "/" + probe, Ingress: draft})
		if err != nil {
			return "NX refused the route: " + err.Error()
		}
		if own.Outcome == "route" && strings.EqualFold(own.Route, name) {
			return "the route would also take NX's own subscription address and send it to itself, so it was not added"
		}
	}
	return ""
}
