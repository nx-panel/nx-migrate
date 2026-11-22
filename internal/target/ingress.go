package target

import (
	"context"
	"encoding/json"
	"fmt"
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
	} `json:"state"`
}

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

// RouteNames lists the routes' names, lower-cased.
func (in *Ingress) RouteNames() map[string]bool {
	out := map[string]bool{}
	for _, raw := range in.Routes {
		var r struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(raw, &r)
		out[strings.ToLower(strings.TrimSpace(r.Name))] = true
	}
	return out
}

// WithRoutes is the document with routes put in front of the existing ones.
// Routes are tried in order, so the added ones are looked at first; each
// takes only its own host and path, so nothing that reached a route before
// reaches another one now.
func (in *Ingress) WithRoutes(routes []any) (map[string]any, error) {
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
	return doc, nil
}

// Ingress reads NX's addresses.
func (c *Client) Ingress(ctx context.Context) (*Ingress, error) {
	var raw map[string]json.RawMessage
	if err := c.http.Get(ctx, "/api/ingress", &raw); err != nil {
		if httpx.Status(err) == http.StatusForbidden {
			return nil, fmt.Errorf("only NX's main admin can read and change the panel's addresses; connect as the main admin")
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
}

// TestRoute asks the panel what a request would get, by the same walk that
// serves it. Nothing is changed.
func (c *Client) TestRoute(ctx context.Context, t RouteTest) (RouteAnswer, error) {
	var out RouteAnswer
	err := c.http.Post(ctx, "/api/ingress/test", t, &out)
	return out, err
}

// ReplaceIngress saves a new table and returns the token that confirms it.
// The panel applies it at once and puts it back unless ConfirmIngress is
// called with that token in time.
func (c *Client) ReplaceIngress(ctx context.Context, doc any) (string, error) {
	var out struct {
		Pending *struct {
			Token string `json:"token"`
		} `json:"pending"`
	}
	if err := c.http.Do(ctx, http.MethodPut, "/api/ingress", doc, &out); err != nil {
		return "", err
	}
	if out.Pending == nil || out.Pending.Token == "" {
		return "", fmt.Errorf("NX saved the change but returned no token to confirm it with, so it will put it back by itself")
	}
	return out.Pending.Token, nil
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

// SubscriptionBase is where NX publishes subscription links, read off an
// account's own link: "https://sub.nx.com/sub" for
// "https://sub.nx.com/sub/abc". It is what the panel itself hands customers,
// so it already accounts for a public address, a subscription domain and a
// path prefix.
func (c *Client) SubscriptionBase(ctx context.Context) (string, error) {
	raw := json.RawMessage{}
	if err := c.http.Get(ctx, "/api/users?limit=1", &raw); err != nil {
		return "", err
	}
	rows, err := decodeList(raw)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("NX has no account yet to read its subscription address from")
	}
	link, _ := rows[0]["subUrl"].(string)
	return subBaseOf(link)
}

func subBaseOf(link string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("NX returned no usable subscription link (%q)", link)
	}
	i := strings.LastIndex(u.Path, "/sub/")
	if i < 0 {
		return "", fmt.Errorf("NX's subscription link %q is not under /sub/", link)
	}
	u.Path, u.RawPath, u.RawQuery, u.Fragment = u.Path[:i+len("/sub")], "", "", ""
	switch h := strings.ToLower(u.Hostname()); {
	case h == "localhost", strings.HasPrefix(h, "127."), h == "::1":
		return "", fmt.Errorf("NX builds its subscription links on %s, which is the address this tool reached it by, not one customers can open: set the panel's public or subscription address in NX first", u.Host)
	}
	return u.String(), nil
}
