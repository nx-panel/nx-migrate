package target

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nx-panel/nx-migrate/internal/httpx"
)

// NX's addresses — the ingress — as a document: GET reads the whole table,
// PUT replaces it, and a change is put back by the panel unless it is
// confirmed with the one-time token the PUT answered with. Both need the main
// admin.
//
// The document is kept as raw JSON, row for row, so what this tool sends back
// is what it read plus its own rows: a field it does not know is not dropped.

// Ingress is the table as read.
type Ingress struct {
	// Doc is the document, top-level field by field.
	Doc map[string]json.RawMessage
	// Routes are the route rows, verbatim and in order.
	Routes []json.RawMessage
	// Listeners are what this tool needs to know of each listener.
	Listeners []IngressListener
	// Pending is set when another change waits for its confirmation; the
	// panel refuses a second one until it is confirmed or put back.
	Pending bool
}

// IngressListener is one listener, as far as placing a route on it goes.
type IngressListener struct {
	Name       string `json:"name"`
	Enabled    *bool  `json:"enabled"`
	ListenPort string `json:"listenPort"`
	// State is how the running panel bound it; its address carries the port
	// actually listened on when ListenPort is left to the start address.
	State *struct {
		Address string `json:"address"`
		// TLS is whether it came up serving TLS.
		TLS bool `json:"tls"`
		// Error is what kept it from binding or from loading its
		// certificate.
		Error string `json:"error"`
	} `json:"state"`
}

// Failed is why the running listener did not come up, "" when it did or
// when the panel does not say.
func (l IngressListener) Failed() string {
	if l.State == nil {
		return ""
	}
	return strings.TrimSpace(l.State.Error)
}

// ServesTLS reports whether the running listener serves TLS.
func (l IngressListener) ServesTLS() bool { return l.State != nil && l.State.TLS }

// On reports whether the listener serves anything.
func (l IngressListener) On() bool { return l.Enabled == nil || *l.Enabled }

// Address is where the listener is bound, as best known.
func (l IngressListener) Address() string {
	if l.State != nil && l.State.Address != "" {
		return l.State.Address
	}
	if l.ListenPort != "" {
		return ":" + strings.TrimPrefix(l.ListenPort, ":")
	}
	return ""
}

// Same reports whether two reads of the table hold the same table: its
// listeners, routes and fallbacks, row for row. How the listeners are
// running is not the table and is not compared.
func (in *Ingress) Same(other *Ingress) bool {
	for _, k := range []string{"routes", "fallbacks"} {
		if !bytes.Equal(compact(in.Doc[k]), compact(other.Doc[k])) {
			return false
		}
	}
	return bytes.Equal(listenerRows(in.Doc["listeners"]), listenerRows(other.Doc["listeners"]))
}

func compact(raw json.RawMessage) []byte {
	var b bytes.Buffer
	if json.Compact(&b, raw) != nil {
		return raw
	}
	return b.Bytes()
}

// listenerRows are the listeners without their running state.
func listenerRows(raw json.RawMessage) []byte {
	var rows []map[string]json.RawMessage
	if json.Unmarshal(raw, &rows) != nil {
		return compact(raw)
	}
	for _, r := range rows {
		delete(r, "state")
	}
	out, _ := json.Marshal(rows)
	return out
}

// ingressRoute is what this tool needs to know of a route row.
type ingressRoute struct {
	Name      string   `json:"name"`
	Hosts     []string `json:"hosts"`
	Service   string   `json:"service"`
	AdminID   uint     `json:"adminId"`
	Canonical bool     `json:"canonical"`
}

func (in *Ingress) routes() []ingressRoute {
	out := make([]ingressRoute, 0, len(in.Routes))
	for _, raw := range in.Routes {
		var r ingressRoute
		_ = json.Unmarshal(raw, &r)
		out = append(out, r)
	}
	return out
}

// RouteNames lists the routes' names, lower-cased.
func (in *Ingress) RouteNames() map[string]bool {
	out := map[string]bool{}
	for _, r := range in.routes() {
		out[strings.ToLower(strings.TrimSpace(r.Name))] = true
	}
	return out
}

// Hosts are every host a route names, lower-cased, wildcards included, in
// the order first named.
func (in *Ingress) Hosts() []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range in.routes() {
		for _, h := range r.Hosts {
			h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
			if h != "" && !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}

// ownSubAdmins are the accounts whose customers' links are published on a
// subscription route of their own (a reseller's domain), not NX's shared
// address.
func (in *Ingress) ownSubAdmins() map[uint]bool {
	out := map[uint]bool{}
	for _, r := range in.routes() {
		if r.Service == "sub" && r.Canonical && r.AdminID != 0 && len(r.Hosts) > 0 {
			out[r.AdminID] = true
		}
	}
	return out
}

// wildcardFor is the wildcard host of a subscription or panel route that
// host is one label under, "" when none is: NX then mints a name like it for
// every subscriber. A wildcard on any other route (a site, a redirect) is
// not where links are published, and a host some route lists by name is not
// a minted one.
func (in *Ingress) wildcardFor(host string) string {
	host = strings.ToLower(host)
	// A name a route lists as itself is published as itself, whatever
	// wildcard is beside it; only a name no route spells out was minted.
	for _, h := range in.Hosts() {
		if h == host {
			return ""
		}
	}
	for _, r := range in.routes() {
		if r.Service != "sub" && r.Service != "panel" {
			continue
		}
		for _, h := range r.Hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			suffix, ok := strings.CutPrefix(h, "*.")
			if !ok {
				continue
			}
			if label, ok := strings.CutSuffix(host, "."+suffix); ok && label != "" && !strings.Contains(label, ".") {
				return h
			}
		}
	}
	return ""
}

// WithRoutes is the document with routes put in front of the existing ones.
// Routes are tried in order, so the added ones are looked at first; it is up
// to each added route to take only what no existing route serves.
func (in *Ingress) WithRoutes(routes []any) map[string]any {
	doc := map[string]any{}
	for k, v := range in.Doc {
		switch k {
		// Read-only parts of the answer, not of the table.
		case "pending", "warnings", "restart", "shaped":
			continue
		}
		doc[k] = v
	}
	all := make([]any, 0, len(routes)+len(in.Routes))
	all = append(all, routes...)
	for _, r := range in.Routes {
		all = append(all, r)
	}
	doc["routes"] = all
	return doc
}

// Ingress reads NX's addresses.
func (c *Client) Ingress(ctx context.Context) (*Ingress, error) {
	var raw map[string]json.RawMessage
	if err := c.http.Get(ctx, "/api/ingress", &raw); err != nil {
		if httpx.Status(err) == http.StatusForbidden {
			return nil, fmt.Errorf("this connection may not read NX's addresses: that needs the main admin, and the ingress:read and ingress:write scopes on an API token (%w)", err)
		}
		return nil, err
	}
	in := &Ingress{Doc: raw}
	if err := json.Unmarshal(raw["routes"], &in.Routes); err != nil {
		return nil, fmt.Errorf("NX answered its addresses in a shape this tool does not recognise (routes): %w", err)
	}
	if err := json.Unmarshal(raw["listeners"], &in.Listeners); err != nil {
		return nil, fmt.Errorf("NX answered its addresses in a shape this tool does not recognise (listeners): %w", err)
	}
	if p := strings.TrimSpace(string(raw["pending"])); p != "" && p != "null" {
		in.Pending = true
	}
	return in, nil
}

// RouteTest is one request described to the panel's route test.
type RouteTest struct {
	Listener string `json:"listener"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	// TLS and SNI describe the handshake, so a listener that refuses names
	// it holds no certificate for says so.
	TLS bool   `json:"tls,omitempty"`
	SNI string `json:"sni,omitempty"`
	// Ingress, when set, is a draft to try instead of the saved table.
	Ingress any `json:"ingress,omitempty"`
}

// RouteAnswer is what that request would get.
type RouteAnswer struct {
	// Outcome is "route", "redirect", "passthrough" or "refused".
	Outcome  string `json:"outcome"`
	Route    string `json:"route"`
	Service  string `json:"service"`
	Path     string `json:"path"`
	Redirect string `json:"redirect"`
	// Closed, on a refusal no route took part in, is why: "listener-off" or
	// "unknown-sni".
	Closed string `json:"closed"`
}

// TestRoute asks the panel what a request would get, by the same walk that
// serves it. Nothing is changed.
func (c *Client) TestRoute(ctx context.Context, t RouteTest) (RouteAnswer, error) {
	var out RouteAnswer
	err := c.http.Post(ctx, "/api/ingress/test", t, &out)
	return out, err
}

// IngressWarning is one thing the panel says a saved table serves, but
// probably not as meant: Code "certificate" names a host (Detail) of route
// Other that no certificate of listener Name carries; "shadowed" a route
// Name that the earlier route Other answers for.
type IngressWarning struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Code   string `json:"code"`
	Other  string `json:"other"`
	Detail string `json:"detail"`
}

// IngressChange is the answer to a saved change.
type IngressChange struct {
	// Token confirms the change.
	Token    string
	Warnings []IngressWarning
	// Restart says the running panel cannot apply the change live: it takes
	// effect at the panel's next start.
	Restart bool
}

// ReplaceIngress saves a new table and returns the token that confirms it.
// The panel applies it at once and puts it back unless ConfirmIngress is
// called with that token in time.
func (c *Client) ReplaceIngress(ctx context.Context, doc any) (IngressChange, error) {
	var out struct {
		Pending *struct {
			Token string `json:"token"`
		} `json:"pending"`
		Warnings []IngressWarning `json:"warnings"`
		Restart  bool             `json:"restart"`
	}
	if err := c.http.Do(ctx, http.MethodPut, "/api/ingress", doc, &out); err != nil {
		return IngressChange{}, err
	}
	if out.Pending == nil || out.Pending.Token == "" {
		return IngressChange{}, fmt.Errorf("NX saved the change but returned no token to confirm it with, so it will put it back by itself")
	}
	return IngressChange{Token: out.Pending.Token, Warnings: out.Warnings, Restart: out.Restart}, nil
}

// ConfirmIngress confirms a change. The panel answers 409 while the change is
// still being applied, and is asked again.
func (c *Client) ConfirmIngress(ctx context.Context, token string) error {
	var err error
	for i := 0; i < 40; i++ {
		err = c.http.Post(ctx, "/api/ingress/confirm", map[string]string{"token": token}, nil)
		if httpx.Status(err) != http.StatusConflict {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return err
}

// subBasePage is how many accounts are read at a time, and subBasePages
// how many pages at most, to find one whose link is on NX's shared address.
const (
	subBasePage  = 100
	subBasePages = 20
)

// SubscriptionBase is where NX publishes the subscription links of accounts
// on its shared address, read off such an account's own link:
// "https://sub.nx.com/sub" for "https://sub.nx.com/sub/abc". It is what the
// panel itself hands customers, so it already accounts for a public address,
// a subscription domain and a path prefix. Accounts whose owner has a
// subscription route of their own (a reseller's domain) are passed over, and
// a subscription domain that mints a name per subscriber is refused: one
// redirect cannot send each customer to their own name.
func (c *Client) SubscriptionBase(ctx context.Context, in *Ingress) (string, error) {
	own := in.ownSubAdmins()
	for page := 0; page < subBasePages; page++ {
		raw := json.RawMessage{}
		path := fmt.Sprintf("/api/users?limit=%d&offset=%d", subBasePage, page*subBasePage)
		if err := c.http.Get(ctx, path, &raw); err != nil {
			return "", err
		}
		rows, err := decodeList(raw)
		if err != nil {
			return "", err
		}
		if len(rows) == 0 && page == 0 {
			return "", fmt.Errorf("NX has no account yet to read its subscription address from")
		}
		for _, row := range rows {
			if id, _ := row["adminId"].(float64); own[uint(id)] {
				continue
			}
			link, _ := row["subUrl"].(string)
			base, err := subBaseOf(link)
			if err != nil {
				return "", err
			}
			u, _ := url.Parse(base)
			if w := in.wildcardFor(u.Hostname()); w != "" {
				return "", fmt.Errorf("NX publishes subscriptions on %s, a name of its own for every subscriber, and one redirect would send every customer to the same subscriber's name: give customers their NX links instead", w)
			}
			return base, nil
		}
		if len(rows) < subBasePage {
			break
		}
	}
	return "", fmt.Errorf("every account NX listed belongs to an admin with a subscription address of their own, so NX's shared subscription address could not be read")
}

func subBaseOf(link string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("NX returned no usable subscription link (%q)", link)
	}
	// On the escaped path: a token is escaped, so a "/sub/" in it is not
	// taken for the panel's own.
	escaped := u.EscapedPath()
	i := strings.LastIndex(escaped, "/sub/")
	if i < 0 {
		return "", fmt.Errorf("NX's subscription link %q is not under /sub/", link)
	}
	path, err := url.PathUnescape(escaped[:i+len("/sub")])
	if err != nil {
		return "", fmt.Errorf("NX returned no usable subscription link (%q)", link)
	}
	u.Path, u.RawPath, u.RawQuery, u.Fragment = path, "", "", ""
	if !reachable(u.Hostname()) {
		return "", fmt.Errorf("NX builds its subscription links on %s, which is the address this tool reached it by, not one customers can open: set the panel's public or subscription address in NX first", u.Host)
	}
	return u.String(), nil
}

// reachable reports whether a host could be one customers open: not
// loopback, a private or link-local address, or a single-label name such as
// a Docker service's.
func reachable(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if ip := net.ParseIP(h); ip != nil {
		return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
	}
	return h != "localhost" && !strings.HasSuffix(h, ".localhost") && strings.Contains(h, ".")
}
