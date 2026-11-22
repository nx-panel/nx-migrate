// Package sublink keeps the old panel's subscription addresses answering.
//
// The token survives on its own: every reader carries it into the account's
// `subId`, and NX resolves `/sub/{subId}`. What does not survive is the rest
// of the link — 3x-ui puts its subscriptions under a random path such as
// `/k3j9x0q2/` on port 2096, s-ui and x-ui under whatever path the operator
// chose, Marzban under `XRAY_SUBSCRIPTION_PATH`. NX always answers
// `{its address}/sub/{token}`, and its own addresses are not touched.
//
// So each old address becomes one item, and applying it adds one route to
// NX's addresses (the ingress): host and path prefix of the old link, a
// redirect to NX's own subscription address, the rest of the path and the
// query kept. `https://sub.old.com:2096/k3j9x0q2/abc` then answers with a
// redirect to `https://sub.nx.com/sub/abc`. Nothing that already exists in the
// ingress is changed; the routes are added in front of it and only take the
// old host and path.
package sublink

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/nx-panel/nx-migrate/internal/bundle"
)

// Old is one address the old panel published subscription links under.
type Old struct {
	// Scheme is "https" or "http", for display.
	Scheme string `json:"scheme"`
	// Host is the link's host name. Empty when the old panel had no domain
	// set and answered on whatever host it was asked by (an IP, usually), so
	// the links customers hold could name any of them.
	Host string `json:"host,omitempty"`
	// Port is the link's port; 0 when the link names none and its scheme's
	// default applies, or when it is not known.
	Port int `json:"port,omitempty"`
	// Path is the part before the token, with no trailing slash: "/sub",
	// "/k3j9x0q2". It is the prefix of the route.
	Path string `json:"path"`
	// Format is the NX format every link under this path was in, for the
	// panels that serve one format per path (3x-ui's JSON and Clash paths).
	// Empty lets the client's own request decide, as NX always does.
	Format string `json:"format,omitempty"`
	// Label names the address for the operator: "subscription",
	// "JSON subscription".
	Label string `json:"label"`
}

// Example is the old link as a customer holds it, with the token spelled
// {token}.
func (o Old) Example() string {
	host := o.Host
	if host == "" {
		host = "{server}"
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if o.Port != 0 && o.Port != defaultPort(o.Scheme) {
		host += ":" + strconv.Itoa(o.Port)
	}
	return o.scheme() + "://" + host + o.Path + "/{token}"
}

func (o Old) scheme() string {
	if o.Scheme == "" {
		return "https"
	}
	return o.Scheme
}

// EffectivePort is the port a customer's client dials: the link's own, or
// its scheme's default when it names none. 0 when not known.
func (o Old) EffectivePort() int {
	if o.Port != 0 {
		return o.Port
	}
	if o.Host == "" {
		return 0
	}
	return defaultPort(o.scheme())
}

func defaultPort(scheme string) int {
	if scheme == "http" {
		return 80
	}
	return 443
}

// FromURL reads an old address from a link base such as
// "https://sub.old.com:2096/k3j9x0q2/" or a relative "/sub/". ok is false
// when it is not something a route could be built from.
func FromURL(base, label, format string) (Old, bool) {
	base = strings.TrimSpace(base)
	if base == "" {
		return Old{}, false
	}
	if !strings.Contains(base, "://") {
		if !strings.HasPrefix(base, "/") {
			return Old{}, false
		}
		return Old{Scheme: "https", Path: CleanPath(base), Label: label, Format: format}, true
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" {
		return Old{}, false
	}
	o := Old{Scheme: strings.ToLower(u.Scheme), Host: strings.ToLower(u.Hostname()),
		Path: CleanPath(u.Path), Label: label, Format: format}
	if p := u.Port(); p != "" {
		o.Port, _ = strconv.Atoi(p)
	}
	if o.Scheme != "http" && o.Scheme != "https" {
		return Old{}, false
	}
	return o, true
}

// FromLink reads an old address from one customer's full link, dropping the
// token that ends it: "https://h/sub/abc" is "https://h/sub". ok is false for
// a link with no path before its token.
func FromLink(link, label string) (Old, bool) {
	link = strings.TrimRight(strings.TrimSpace(link), "/")
	if q := strings.IndexAny(link, "?#"); q >= 0 {
		link = link[:q]
	}
	i := strings.LastIndex(link, "/")
	if i < 0 {
		return Old{}, false
	}
	return FromURL(link[:i+1], label, "")
}

// CleanPath is a path prefix as a route takes it: leading slash, no trailing
// one, "" for the root.
func CleanPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

// segment is what NX accepts in one segment of a route prefix.
var segment = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// PrefixProblem says why a path cannot be a route prefix, or "" when it can.
func PrefixProblem(p string) string {
	if p == "" {
		return "the old links sat at the root of their address, and a redirect there would take every path of that host — the panel's own pages included"
	}
	for _, seg := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if seg == "." || seg == ".." || !segment.MatchString(seg) {
			return fmt.Sprintf("the old path %q has characters NX does not accept in a route prefix (letters, digits and - . _ ~ only)", p)
		}
	}
	return ""
}

// Key identifies an address: two readers' spellings of the same one are one
// item.
func (o Old) Key() string {
	return fmt.Sprintf("%s|%d|%s|%s", o.Host, o.EffectivePort(), o.Path, o.Format)
}

// RouteName is the name of the route this address becomes, stable across
// runs so a second import finds the route the first one added.
func (o Old) RouteName() string {
	host := o.Host
	if host == "" {
		host = "any-host"
	}
	parts := []string{"old-sub", host}
	if p := o.EffectivePort(); p != 0 {
		parts = append(parts, strconv.Itoa(p))
	}
	if o.Path != "" {
		parts = append(parts, o.Path)
	}
	if o.Format != "" {
		parts = append(parts, o.Format)
	}
	name := strings.Trim(nonName.ReplaceAllString(strings.ToLower(strings.Join(parts, "-")), "-"), "-")
	if len(name) > 64 {
		name = strings.TrimRight(name[:64], "-")
	}
	return name
}

var nonName = regexp.MustCompile(`[^a-z0-9]+`)

// Item is the bundle item for one address.
func (o Old) Item() bundle.Item {
	payload, _ := json.Marshal(o)
	it := bundle.Item{
		ID: "sublink:" + o.Key(), Kind: bundle.KindSubLink,
		Name: o.Example(), SourceName: o.Label, Payload: payload,
	}
	it.Set("address", o.Label)
	it.Set("old link", o.Example())
	if o.Format != "" {
		it.Set("format", o.Format)
	}
	if o.Host == "" {
		it.AddNote("the old panel had no domain for its subscriptions and answered on any host it was reached by, so this redirect takes the path on every host that reaches NX except NX's own subscription address")
	}
	if o.Path == "/sub" && o.Format == "" {
		it.AddNote("this is NX's own path, so where NX already answers this host there is nothing to add and the transfer says so")
	}
	if problem := PrefixProblem(o.Path); problem != "" {
		it.Block("%s; give the customers their NX link instead", problem)
	}
	return it
}

// Add puts one item per distinct address into the bundle, with a note that
// applies to all of them.
func Add(b *bundle.Bundle, olds []Old, notes ...string) {
	seen := map[string]bool{}
	for _, o := range olds {
		if seen[o.Key()] {
			continue
		}
		seen[o.Key()] = true
		it := o.Item()
		for _, n := range notes {
			it.AddNote("%s", n)
		}
		b.Add(it)
	}
}

// Decode reads an item's payload back.
func Decode(it bundle.Item) (Old, error) {
	var o Old
	if err := json.Unmarshal(it.Payload, &o); err != nil {
		return o, fmt.Errorf("this item's address could not be read back: %w", err)
	}
	return o, nil
}

// portOf is the port of a "host:port" listen address, 0 when it has none.
func portOf(addr string) int {
	_, p, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}
