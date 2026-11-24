package sublink

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nx-panel/nx-migrate/internal/bundle"
	"github.com/nx-panel/nx-migrate/internal/httpx"
	"github.com/nx-panel/nx-migrate/internal/target"
)

// Outcome is how one address ended.
type Outcome struct {
	Item    bundle.Item
	Status  Status
	Message string
}

// Status is how an address ended.
type Status string

// The statuses an address ends with.
const (
	Created Status = "created"
	Exists  Status = "exists"
	Failed  Status = "failed"
	// Skipped is an address the run was stopped before.
	Skipped Status = "skipped"
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

// planned is an address about to become a route.
type planned struct {
	item      bundle.Item
	old       Old
	name      string
	route     map[string]any
	listeners []string
	note      string
}

func routesOf(plan []planned) []any {
	out := make([]any, 0, len(plan))
	for _, p := range plan {
		out = append(out, p.route)
	}
	return out
}

const (
	stoppedBefore = "the run was stopped before NX's addresses were changed"
	stoppedAfter  = "the run was stopped after the change was saved; it was not confirmed, so NX puts it back by itself within two minutes"
)

func apply(ctx context.Context, c *target.Client, items []bundle.Item) []Outcome {
	out := make([]Outcome, 0, len(items))
	end := func(its []bundle.Item, st Status, msg string) []Outcome {
		for _, it := range its {
			out = append(out, Outcome{Item: it, Status: st, Message: msg})
		}
		return out
	}
	endPlan := func(plan []planned, st Status, msg string) []Outcome {
		for _, p := range plan {
			out = append(out, Outcome{Item: p.item, Status: st, Message: msg})
		}
		return out
	}
	// stopped skips every item that has no outcome yet — those still to be
	// looked at and those already planned alike — when the run is stopped.
	stopped := func() []Outcome {
		done := make(map[string]bool, len(out))
		for _, o := range out {
			done[o.Item.ID] = true
		}
		var rest []bundle.Item
		for _, it := range items {
			if !done[it.ID] {
				rest = append(rest, it)
			}
		}
		return end(rest, Skipped, stoppedBefore)
	}
	// failAll ends every item, or skips them all when the run was stopped:
	// a cancelled request is not the address's failure.
	failAll := func(format string, args ...any) []Outcome {
		if ctx.Err() != nil {
			return end(items, Skipped, stoppedBefore)
		}
		return end(items, Failed, fmt.Sprintf(format, args...))
	}

	in, err := c.Ingress(ctx)
	if err != nil {
		return failAll("NX's addresses could not be read: %v", err)
	}
	if in.Pending {
		return failAll("another change to NX's addresses is waiting for its confirmation; confirm it or let it be put back, then run the transfer again with these ticked")
	}
	base, err := c.SubscriptionBase(ctx, in)
	if err != nil {
		return failAll("NX's own subscription address could not be read, so there is nothing to send the old links to: %v", err)
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return failAll("NX's own subscription address %q could not be read: %v", base, err)
	}
	// A hostless redirect takes the old path on every host but those a route
	// of NX's names, so nothing NX serves on a host of its own is taken. NX's
	// own subscription host is not excluded for being that: when it is an IP
	// it is usually the very address the old hostless links name, and the
	// draft test below proves NX's own links never meet a redirect.
	exclude := in.Hosts()
	names := in.RouteNames()

	var plan []planned
	for _, it := range items {
		if ctx.Err() != nil {
			return stopped()
		}
		o, err := Decode(it)
		if err != nil {
			out = append(out, Outcome{Item: it, Status: Failed, Message: err.Error()})
			continue
		}
		if problem := prefixProblem(o.Path); problem != "" {
			out = append(out, Outcome{Item: it, Status: Failed, Message: problem})
			continue
		}
		if o.Host != "" {
			if h, err := normalHost(o.Host); err != nil || h != o.Host {
				out = append(out, Outcome{Item: it, Status: Failed, Message: fmt.Sprintf("the old host %q is not a host name NX can route", o.Host)})
				continue
			}
		}
		name := o.RouteName()
		if names[name] {
			out = append(out, Outcome{
				Item: it, Status: Exists,
				Message: fmt.Sprintf("NX already has the route %q for this address, so it was left alone", name),
			})
			continue
		}
		listeners, note := listenersFor(in.Listeners, o)
		if len(listeners) == 0 {
			out = append(out, Outcome{Item: it, Status: Failed, Message: "NX has no listener switched on and serving to put the route on"})
			continue
		}
		works, clash, err := current(ctx, c, o, in.Listeners, listeners)
		if err != nil {
			if ctx.Err() != nil {
				return stopped()
			}
			out = append(out, Outcome{Item: it, Status: Failed, Message: testFailure(err)})
			continue
		}
		if clash != "" {
			out = append(out, Outcome{Item: it, Status: Failed, Message: clash})
			continue
		}
		if works {
			msg := "NX already answers this address with its subscriptions, so there was nothing to add"
			if note != "" {
				msg += "; but " + note
			}
			out = append(out, Outcome{Item: it, Status: Exists, Message: msg})
			continue
		}
		names[name] = true
		plan = append(plan, planned{
			item: it, old: o, name: name, route: route(o, name, listeners, base, exclude),
			listeners: listeners, note: note,
		})
	}
	if len(plan) == 0 {
		return out
	}

	// Ask the panel about the draft before saving it: each old link must
	// meet its own redirect, and NX's own subscription address must not meet
	// any of them — that would be a redirect to itself.
	draft := in.WithRoutes(routesOf(plan))
	var keep []planned
	for _, p := range plan {
		msg, err := verify(ctx, c, draft, p, in.Listeners)
		if err != nil && ctx.Err() != nil {
			return stopped()
		}
		if msg != "" {
			out = append(out, Outcome{Item: p.item, Status: Failed, Message: msg})
			continue
		}
		keep = append(keep, p)
	}
	keep, draft, err = keepOffOwnAddress(ctx, c, in, keep, baseURL, &out)
	if err != nil {
		if ctx.Err() != nil {
			return stopped()
		}
		return endPlan(keep, Failed, testFailure(err))
	}
	if len(keep) == 0 {
		return out
	}

	// The table is put back whole, so it must still be the one read: the
	// panel takes a PUT without asking which version it replaces.
	now, err := c.Ingress(ctx)
	switch {
	case ctx.Err() != nil:
		return stopped()
	case err != nil:
		return endPlan(keep, Failed, "NX's addresses could not be read again before the change: "+err.Error())
	case now.Pending || !now.Same(in):
		return endPlan(keep, Failed, "NX's addresses changed while this run was checking them, so nothing was saved: run the transfer again with these ticked")
	}

	ours := map[string]bool{}
	for _, p := range keep {
		ours[strings.ToLower(p.name)] = true
	}
	change, err := c.ReplaceIngress(ctx, draft)
	switch {
	case err != nil && ctx.Err() != nil:
		// The PUT may or may not have landed; unconfirmed, it goes back.
		return endPlan(keep, Skipped, stoppedAfter)
	case err != nil && target.IsConfirmRequired(err):
		err = fmt.Errorf("NX wants a fresh authenticator code before it changes its addresses: run the transfer again with only these ticked, entering a new code before it starts")
	case err != nil:
	default:
		if taken := takesFromNX(change.Warnings, ours); taken != "" {
			// Not confirmed, so the panel puts the table back by itself.
			err = fmt.Errorf("NX says the new routes would take %s, so the change was not confirmed and the panel puts it back by itself within two minutes", taken)
		} else if err = confirm(ctx, c, change.Token); err != nil {
			err = fmt.Errorf("NX saved the routes but the change could not be confirmed (%w), so the panel puts it back by itself within two minutes", err)
		}
	}
	if err != nil {
		return endPlan(keep, Failed, err.Error())
	}
	for _, p := range keep {
		to := redirectExample(base, p.old.Format)
		msg := fmt.Sprintf("added the route %q: %s now redirects to %s", p.name, p.old.Example(), to)
		if change.Restart {
			msg = fmt.Sprintf("added the route %q: %s redirects to %s once the panel is restarted, since the running panel cannot apply it live",
				p.name, p.old.Example(), to)
		}
		if p.note != "" {
			msg += "; " + p.note
		}
		if p.old.scheme() == "https" && baseURL.Scheme == "http" {
			msg += "; NX publishes its links on plain http, so customers who fetched over https are sent to http and their tokens travel unencrypted: give NX an https public or subscription address"
		}
		for _, w := range warningsFor(change.Warnings, p.name) {
			msg += "; " + w
		}
		out = append(out, Outcome{Item: p.item, Status: Created, Message: msg})
	}
	return out
}

// confirm confirms a saved change. Once the change is saved it is confirmed
// whatever happens to the run: stopping half-way through the confirmation
// would leave the outcome unknown — confirmed on the panel, reported as put
// back. The panel's own window bounds the wait.
func confirm(ctx context.Context, c *target.Client, token string) error {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), confirmWait)
	defer cancel()
	return c.ConfirmIngress(cctx, token)
}

// confirmWait is how long a confirmation is waited for; the panel puts an
// unconfirmed change back after two minutes.
const confirmWait = 60 * time.Second

// testFailure says why a route test failed: the panel refusing the draft
// (400), or the test not reaching it.
func testFailure(err error) string {
	if httpx.Status(err) == http.StatusBadRequest {
		return "NX refused the route: " + err.Error()
	}
	return "NX's route test could not be asked: " + err.Error()
}

// keepOffOwnAddress asks, once per listener, whether NX's own subscription
// address meets one of the new routes in the draft, drops that route with an
// outcome, and asks again until none does. It returns what is kept and the
// draft of it.
func keepOffOwnAddress(ctx context.Context, c *target.Client, in *target.Ingress, keep []planned, base *url.URL, out *[]Outcome) ([]planned, map[string]any, error) {
	var listeners []string
	seen := map[string]bool{}
	for _, p := range keep {
		for _, l := range p.listeners {
			if !seen[strings.ToLower(l)] {
				seen[strings.ToLower(l)] = true
				listeners = append(listeners, l)
			}
		}
	}
	for len(keep) > 0 {
		draft := in.WithRoutes(routesOf(keep))
		hit := -1
		for _, l := range listeners {
			own, err := c.TestRoute(ctx, target.RouteTest{Listener: l, Host: base.Hostname(), Path: base.Path + "/" + probe, Ingress: draft})
			if err != nil {
				return keep, draft, err
			}
			if own.Outcome != "route" {
				continue
			}
			for i, p := range keep {
				if strings.EqualFold(own.Route, p.name) {
					hit = i
				}
			}
			if hit >= 0 {
				break
			}
		}
		if hit < 0 {
			return keep, draft, nil
		}
		*out = append(*out, Outcome{
			Item: keep[hit].item, Status: Failed,
			Message: "the route would also take NX's own subscription address and send it to itself, so it was not added",
		})
		keep = append(keep[:hit:hit], keep[hit+1:]...)
	}
	return keep, nil, nil
}

// takesFromNX names what a route of ours takes from one of NX's, by the
// panel's own warnings on the saved change; "" when nothing.
func takesFromNX(warnings []target.IngressWarning, ours map[string]bool) string {
	for _, w := range warnings {
		if w.Code == "shadowed" && ours[strings.ToLower(w.Other)] && !ours[strings.ToLower(w.Name)] {
			return fmt.Sprintf("%s from NX's route %q", w.Detail, w.Name)
		}
	}
	return ""
}

// warningsFor are the panel's warnings about one of the new routes, said
// for the operator.
func warningsFor(warnings []target.IngressWarning, name string) []string {
	var out []string
	for _, w := range warnings {
		switch {
		case w.Code == "certificate" && strings.EqualFold(w.Other, name):
			out = append(out, fmt.Sprintf("NX holds no certificate for %s on its listener %q, so an https client fails the handshake before it sees the redirect: add a certificate for that name in NX", w.Detail, w.Name))
		case w.Code == "shadowed" && strings.EqualFold(w.Name, name):
			out = append(out, fmt.Sprintf("NX's route %q answers %s first, so this redirect does not", w.Other, w.Detail))
		case w.Code == "never-answers" && strings.EqualFold(w.Name, name):
			out = append(out, fmt.Sprintf("NX says nothing reaches this route (%s)", w.Detail))
		}
	}
	return out
}

// listenersFor are the listeners an old link can arrive on: those bound to
// its port, or — when none is, or the port is not known — every listener that
// serves, since a proxy in front of NX may bring that port to any of them. A
// listener switched off, or one that did not come up, serves nothing. The
// note says what the operator should know: no listener on the port, one that
// failed there, or one whose TLS does not match the link's scheme.
func listenersFor(all []target.IngressListener, o Old) ([]string, string) {
	port := o.effectivePort()
	var on, matching, notes []string
	for _, l := range all {
		if !l.On() {
			continue
		}
		bound := port != 0 && portOf(l.Address()) == port
		if l.Failed() != "" {
			if bound {
				notes = append(notes, fmt.Sprintf("NX's listener %q on port %d did not come up (%s)", l.Name, port, l.Failed()))
			}
			continue
		}
		on = append(on, l.Name)
		if !bound {
			continue
		}
		matching = append(matching, l.Name)
		if l.State == nil {
			continue
		}
		switch https := o.scheme() == "https"; {
		case https && !l.ServesTLS():
			notes = append(notes, fmt.Sprintf("NX's listener %q on port %d serves plain HTTP while the old links are https, so clients fail the handshake unless something in front of NX terminates TLS", l.Name, port))
		case !https && l.ServesTLS():
			notes = append(notes, fmt.Sprintf("NX's listener %q on port %d serves TLS while the old links are plain http, so clients fail unless something in front of NX speaks TLS to it", l.Name, port))
		}
	}
	if len(matching) > 0 {
		return matching, strings.Join(notes, "; ")
	}
	if port != 0 {
		notes = append(notes, fmt.Sprintf("no NX listener serves port %d, so the route is on every listener: it answers once that port reaches NX, through a listener on it or a proxy in front", port))
	}
	return on, strings.Join(notes, "; ")
}

// current asks the saved table about the old link. works is set when NX
// already answers it with its subscriptions on every listener it can arrive
// on; clash names what of NX's the old path would be taken from, or a
// handshake NX refuses for the old name.
func current(ctx context.Context, c *target.Client, o Old, all []target.IngressListener, listeners []string) (works bool, clash string, err error) {
	works = true
	for _, l := range listeners {
		a, err := c.TestRoute(ctx, request(o, all, l, nil))
		if err != nil {
			return false, "", err
		}
		if a.Closed == "unknown-sni" {
			return false, fmt.Sprintf("NX's listener %q refuses a TLS handshake for %s, since it holds no certificate for that name: add one in NX, then run the transfer again with this ticked", l, o.Host), nil
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

// request is the route test for the old link on one listener: its host and
// a token's path, and a TLS handshake naming the host when the link is https
// and the listener serves TLS.
func request(o Old, all []target.IngressListener, listener string, draft any) target.RouteTest {
	t := target.RouteTest{Listener: listener, Host: testHost(o), Path: o.Path + "/" + probe, Ingress: draft}
	if o.scheme() == "https" {
		for _, l := range all {
			if strings.EqualFold(l.Name, listener) && l.ServesTLS() {
				t.TLS = true
				if o.Host != "" && net.ParseIP(o.Host) == nil {
					t.SNI = o.Host
				}
			}
		}
	}
	return t
}

// subProbe is the path NX's subscription service sees for a link it serves:
// NX mounts /sub/{token}, so a token one segment under /sub and nothing else.
const subProbe = "/sub/" + probe

// servesSub reports whether an answer is NX's subscription service, serving
// the probe as a token.
func servesSub(a target.RouteAnswer) bool {
	return (a.Service == "sub" || a.Service == "panel") && a.Path == subProbe
}

// panelPaths are the paths NX's panel really serves: its API, installer,
// metrics and assets, and the pages of its single-page app a browser loads
// directly (nx-panel frontend/src/router/index.ts). Any other path the app
// answers is its catch-all.
var panelPaths = []string{
	"/api", "/install", "/metrics", "/assets",
	"/login", "/setup", "/ingress-confirm", "/dashboard", "/users", "/plans", "/inbounds",
	"/outbounds", "/endpoints", "/rule-sets", "/fronting", "/certificates", "/templates",
	"/nodes", "/tunnels", "/settings", "/services", "/admins", "/roles", "/tokens", "/audit",
	"/license",
}

// takenFromNX reports whether an answer is something of NX's own that a
// redirect must not cover: its API, its subscriptions, a proxied site. The panel's single-page app answers every path it
// does not know, so a panel route counts only for the paths it really serves;
// under /sub that is a token one segment down, and a deeper old path such as
// /sub/vpn is not one NX serves.
func takenFromNX(a target.RouteAnswer) bool {
	switch a.Service {
	case "panel":
		for _, p := range panelPaths {
			if a.Path == p || strings.HasPrefix(a.Path, p+"/") {
				return true
			}
		}
		return a.Path == subProbe || a.Path == "/install-node.sh"
	case "sub":
		return a.Path == subProbe
	case "", "static", "redirect", "canned":
		// Nothing, or a service that answers every path the same way (a
		// decoy page, an http → https redirect): a path taken from it is
		// not one it serves.
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
func route(o Old, name string, listeners []string, base string, exclude []string) map[string]any {
	r := map[string]any{
		"name":      name,
		"listeners": listeners,
		"hosts":     []string{},
		"prefix":    o.Path,
		"service":   "redirect",
		// 302, not 301: a permanent redirect is kept by clients for good,
		// and this one is meant to be removable.
		"reply": map[string]any{"to": redirectTo(base, o.Format), "code": 302, "keepPath": true},
	}
	if o.Host != "" {
		r["hosts"] = []string{o.Host}
	} else if len(exclude) > 0 {
		r["excludeHosts"] = exclude
	}
	return r
}

// redirectTo is where a redirect for the given format points.
func redirectTo(base, format string) string {
	if format == "" {
		return base
	}
	return base + "?format=" + url.QueryEscape(format)
}

// redirectExample is that address with a token, for the operator.
func redirectExample(base, format string) string {
	to := redirectTo(base, format)
	u, err := url.Parse(to)
	if err != nil {
		return to
	}
	u.Path += "/{token}"
	return strings.Replace(u.String(), "%7Btoken%7D", "{token}", 1)
}

// verify asks the panel whether the old link meets its own new route in the
// draft on every listener it is on. msg is why not; err a test that could not
// be asked.
func verify(ctx context.Context, c *target.Client, draft any, p planned, all []target.IngressListener) (msg string, err error) {
	for _, l := range p.listeners {
		a, err := c.TestRoute(ctx, request(p.old, all, l, draft))
		if err != nil {
			return testFailure(err), err
		}
		if a.Outcome != "route" || !strings.EqualFold(a.Route, p.name) {
			got := a.Route
			if got == "" {
				got = a.Outcome
			}
			return fmt.Sprintf("NX would not send the old link to its new route but to %q; add the redirect by hand", got), nil
		}
	}
	return "", nil
}
