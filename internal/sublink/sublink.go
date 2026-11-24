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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/idna"

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

// effectivePort is the port a customer's client dials: the link's own, or
// its scheme's default when it names none. 0 when not known.
func (o Old) effectivePort() int {
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

// fromURL reads an old address from a link base such as
// "https://sub.old.com:2096/k3j9x0q2/" or a relative "/sub/". ok is false
// when it is not an http(s) address with a usable host and port, or a
// relative path. A path at the root is read (Path ""); the item made of it is
// blocked, since a redirect there would take the whole host.
func fromURL(base, label, format string) (Old, bool) {
	base = strings.TrimSpace(base)
	if base == "" {
		return Old{}, false
	}
	if !strings.Contains(base, "://") {
		if !strings.HasPrefix(base, "/") {
			return Old{}, false
		}
		return Old{Scheme: "https", Path: cleanPath(base), Label: label, Format: format}, true
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" {
		return Old{}, false
	}
	host, err := normalHost(u.Hostname())
	if err != nil {
		return Old{}, false
	}
	o := Old{Scheme: strings.ToLower(u.Scheme), Host: host, Path: cleanPath(u.Path), Label: label, Format: format}
	if p := u.Port(); p != "" {
		if o.Port, err = strconv.Atoi(p); err != nil || o.Port < 1 || o.Port > 65535 {
			return Old{}, false
		}
	}
	if o.Scheme != "http" && o.Scheme != "https" {
		return Old{}, false
	}
	return o, true
}

// FromLink reads an old address from one customer's full link, dropping the
// token that ends it: "https://h/sub/abc" is "https://h/sub". ok is false
// when what is left is not an address fromURL reads; a token at the root
// ("https://h/abc") is read with an empty path, as fromURL says.
func FromLink(link, label string) (Old, bool) {
	link = strings.TrimRight(strings.TrimSpace(link), "/")
	if q := strings.IndexAny(link, "?#"); q >= 0 {
		link = link[:q]
	}
	i := strings.LastIndex(link, "/")
	if i < 0 {
		return Old{}, false
	}
	return fromURL(link[:i+1], label, "")
}

// hostLabel is one label of a host name as NX takes it, after punycode:
// letters, digits, hyphens and underscores, which is what DNS serves and the
// panel's host check lets through ("my_sub", "r3---sn-abc", "a-").
var hostLabel = regexp.MustCompile(`^[a-z0-9_-]{1,63}$`)

// normalHost is a host as a client sends it: lower-cased, without a trailing
// dot, an internationalised name in punycode (a client asks for
// xn--e1afmkfd.xn--p1ai, never пример.рф). An IP address is kept as written,
// without brackets: the panel matches a host by its spelling, and a client
// sends the literal its link holds. An error says why it is not a host name
// at all ("sub.old.com/", "https://sub.old.com", "sub.old.com:2096").
func normalHost(h string) (string, error) {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if h == "" {
		return "", fmt.Errorf("no host name")
	}
	if bare := strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"); net.ParseIP(bare) != nil {
		return bare, nil
	}
	ascii := h
	if !isASCII(h) {
		var err error
		if ascii, err = idna.Lookup.ToASCII(h); err != nil {
			return "", fmt.Errorf("%q is not a host name", h)
		}
	}
	if len(ascii) > 253 {
		return "", fmt.Errorf("%q is not a host name", h)
	}
	for _, l := range strings.Split(ascii, ".") {
		if !hostLabel.MatchString(l) {
			return "", fmt.Errorf("%q is not a host name", h)
		}
	}
	return ascii, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// cleanPath is a path prefix as a route takes it: leading slash, no trailing
// one, "" for the root.
func cleanPath(p string) string {
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

// prefixProblem says why a path cannot be a route prefix, or "" when it can.
func prefixProblem(p string) string {
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
	return fmt.Sprintf("%s|%d|%s|%s", o.Host, o.effectivePort(), o.Path, o.Format)
}

// RouteName is the name of the route this address becomes, stable across
// runs so a second import finds the route the first one added. It ends in a
// hash of the address, so two addresses that spell alike ("/sub.v2" and
// "/sub-v2") or that a long host cuts short never share a name.
func (o Old) RouteName() string {
	host := o.Host
	if host == "" {
		host = "any-host"
	}
	parts := []string{"old-sub", host}
	if p := o.effectivePort(); p != 0 {
		parts = append(parts, strconv.Itoa(p))
	}
	if o.Path != "" {
		parts = append(parts, o.Path)
	}
	if o.Format != "" {
		parts = append(parts, o.Format)
	}
	sum := sha256.Sum256([]byte(o.Key()))
	suffix := "-" + hex.EncodeToString(sum[:4])
	name := strings.Trim(nonName.ReplaceAllString(strings.ToLower(strings.Join(parts, "-")), "-"), "-")
	// NX takes names of up to 64 characters.
	if limit := 64 - len(suffix); len(name) > limit {
		name = strings.TrimRight(name[:limit], "-")
	}
	return name + suffix
}

var nonName = regexp.MustCompile(`[^a-z0-9]+`)

// CautionNote is why an address item is left unticked: it is the one part
// of a run that changes NX's own addresses.
const CautionNote = "not ticked unless you tick it: this changes NX's own addresses (its ingress), which can upset its other settings — NX's Settings page and an admin's subscription domain stop editing the addresses, and a self-signed panel certificate gains the old names. Setting the redirect up yourself on NX's Ingress page is the better way"

// KeepNote is what every address item says of the customers' links.
const KeepNote = "customers keep this link: NX answers it with a redirect to its own subscription address and the same token. Point this address (its DNS name and port) at NX before the old panel is switched off"

// defaultSubPort is the port s-ui, 3x-ui and x-ui serve subscriptions on
// when `subPort` has no row.
const defaultSubPort = 2096

// Settings are the subscription settings of the SQLite panels (s-ui, 3x-ui
// and the x-ui line), which spell them alike. A key with no row has the
// panel's default.
type Settings map[string]string

// Get is a setting, or def when it has no value.
func (s Settings) Get(key, def string) string {
	if v := strings.TrimSpace(s[key]); v != "" {
		return v
	}
	return def
}

// On is a boolean setting, or def when it has no value.
func (s Settings) On(key string, def bool) bool {
	v := strings.TrimSpace(s[key])
	if v == "" {
		return def
	}
	return v == "true"
}

// Old is the address one of the panel's subscription paths is published
// under: its own URI setting when the operator set one (a reverse proxy in
// front), else the subscription server's scheme, domain, port and that path.
// An error says which setting holds something the old panel could not have
// published links under, and the address is then not offered.
func (s Settings) Address(uriKey, pathKey, defPath, label, format string) (Old, error) {
	if uri := s.Get(uriKey, ""); uri != "" {
		o, ok := fromURL(uri, label, format)
		if !ok {
			return Old{}, fmt.Errorf("the %s setting %q is not an http or https address with a host name and port NX can route", uriKey, uri)
		}
		return o, nil
	}
	scheme := "http"
	if s.Get("subCertFile", "") != "" && s.Get("subKeyFile", "") != "" {
		scheme = "https"
	}
	raw := s.Get("subPort", strconv.Itoa(defaultSubPort))
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return Old{}, fmt.Errorf("the subPort setting %q is not a port", raw)
	}
	var host string
	if d := s.Get("subDomain", ""); d != "" {
		if host, err = normalHost(d); err != nil {
			return Old{}, fmt.Errorf("the subDomain setting: %w", err)
		}
	}
	return Old{
		Scheme: scheme, Host: host, Port: port,
		Path: cleanPath(s.Get(pathKey, defPath)), Label: label, Format: format,
	}, nil
}

// Base is the old link before its token, for showing a customer's link:
// "https://sub.old.com:2096/k3j9x0q2/". "" when the old panel had no domain,
// so the link names a host this tool cannot know.
func (o Old) Base() string {
	if o.Host == "" {
		return ""
	}
	return strings.TrimSuffix(o.Example(), "{token}")
}

// Item is the bundle item for one address.
func (o Old) Item() bundle.Item {
	payload, _ := json.Marshal(o)
	it := bundle.Item{
		ID: "sublink:" + o.Key(), Kind: bundle.KindSubLink,
		Name: o.Example(), SourceName: o.Label, Payload: payload,
	}
	it.Set("address", o.Label)
	it.Set("old link", o.Example())
	it.AddNote("%s", CautionNote)
	if o.Format != "" {
		it.Set("format", o.Format)
	}
	if o.Host == "" {
		it.AddNote("the old panel had no domain for its subscriptions and answered on any host it was reached by, so this redirect takes the path on every host that reaches NX except those a route of NX's names")
	}
	if o.Path == "/sub" && o.Format == "" {
		it.AddNote("this is NX's own path, so where NX already answers this host there is nothing to add and the transfer says so")
	}
	if problem := prefixProblem(o.Path); problem != "" {
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
