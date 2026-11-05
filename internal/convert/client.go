package convert

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nx-panel/nx-migrate/internal/bundle"
	"github.com/nx-panel/nx-migrate/internal/normalize"
)

// Client is the shape every source reader reduces one account to. It is
// deliberately NX's vocabulary rather than any source panel's, so the
// awkward parts of each panel — a single traffic counter, unlimited spelled as
// -1 or null, a lifetime that has not started — are resolved inside the reader
// where the panel's own semantics are known, not later where they are not.
type Client struct {
	// SourceID makes the bundle item id stable across re-runs.
	SourceID string
	Name     string
	Enable   bool

	// One credential set, which is all NX keeps. A source that stores
	// credentials per protocol resolves the conflict before filling these in
	// and records what it discarded in Conflicts.
	UUID     string
	Password string
	Flow     string
	Method   string
	// Conflicts names the protocols whose credentials could not be carried.
	Conflicts []string

	// Quota and lifetime. Zero means unlimited / never, exactly as in NX,
	// so a reader must normalise -1 and null before setting these.
	Volume int64
	Expiry int64 // unix seconds
	// Duration turns Expiry into a length that starts at first use. Set it only
	// when the source really has that shape; ActivatedAt carries the start over
	// for an account that has already begun.
	Duration    int64
	ActivatedAt int64

	Up   int64
	Down int64
	// SingleCounter marks a source that only kept one total. Everything lands
	// in Down and the item says so.
	SingleCounter bool

	SpeedLimit int64
	IPLimit    int

	// The periodic reset, in NX's own shape: an empty ResetPeriod is the
	// rolling cycle measured in ResetDays, and a calendar cycle
	// ("weekly"/"monthly"/"yearly") is anchored to ResetStartDay.
	//
	// Every source panel spells "monthly" as a strategy rather than a day
	// count, and this tool used to write 30 days for it — which moves every
	// migrated customer's reset day and keeps moving it, about five days a
	// year. NX has calendar periods now, so the mapping is exact.
	AutoReset     bool
	ResetDays     int
	ResetPeriod   string
	ResetStartDay int

	// SubID carries the old panel's subscription token. NX resolves
	// /sub/{id} against sub_id as well as sub_token, so an old link keeps
	// working once the hostname points here.
	SubID string
	// SubURL is the full old link, shown in the review table so an operator can
	// see what continuity they are getting.
	SubURL string

	Group    string
	Desc     string
	Remark   string
	OnlineAt int64

	// Contact is the customer's own details on the NX side: telegram_id,
	// email and phone, plus whatever else a source keeps about a person. Every
	// panel this tool reads has *somewhere* to write a customer's email or
	// Telegram id, and until NX had a column for it the importer read the
	// field, showed it in the review table and then dropped it — the operator's
	// contact list, lost in the one step that was supposed to preserve
	// everything. Written with SetContact so an empty value is never a key.
	Contact map[string]string

	// OwnerItem is the bundle id of the admin that owns this account, if the
	// source has resellers and that admin is in the bundle.
	OwnerItem string
	// TemplateItems are the bundle ids of the templates the account should be
	// provisioned on. Empty means every template.
	TemplateItems []string
	// InboundTags narrows the account to these inbounds of its templates, by
	// NX tag, as the old panel had it: 3x-ui and s-ui put each client on
	// chosen inbounds, and NX's equivalent is the account's config filter (a
	// `tag in …` rule). Empty means every inbound. Set it with LimitToInbounds.
	InboundTags []string
	// WGPrivateKey is the account's own WireGuard key (base64), from a panel
	// that gives each account one. NX keeps it in the account's config and
	// derives the public key from it, so the customer keeps the key it has.
	WGPrivateKey string
	// NextReset is the next usage reset (unix seconds) when the old panel
	// counts its cycle from a date of its own, rather than from the day the
	// account arrives in NX. 0 lets the panel open the cycle itself.
	NextReset int64
	// EndpointTags narrows the account to these WireGuard endpoints, the way
	// InboundTags narrows its inbounds. Set it with LimitToEndpoints.
	EndpointTags []string
	// InboundsOff and EndpointsOff are every one of them, for an account the
	// old panel put on none of those the others had: "in nothing" cannot be
	// said, "not in these" can.
	InboundsOff  []string
	EndpointsOff []string
	// OnlyUncarried is an account the old panel had only on inbounds that
	// cannot come to NX (MASQUE, an unknown transport…). It is not limited.
	OnlyUncarried bool
}

// CarriedNames maps the id of every item that will be carried to its NX name
// (an inbound's is its tag). A blocked item is left out: an account limited
// to an inbound that never reaches NX would reach nothing at all.
func CarriedNames(b *bundle.Bundle) map[string]string {
	out := make(map[string]string, len(b.Items))
	for _, it := range b.Items {
		if it.Severity != bundle.SevBlocked {
			out[it.ID] = it.Name
		}
	}
	return out
}

// MaxFilterValues is the panel's cap on the values of one config-filter rule.
const MaxFilterValues = 64

// LimitToInbounds records the inbounds an account was on, given every inbound
// its template carries. An account on all of them needs no filter, and gets
// none: a filter is a restriction, and one that names everything would only
// stop the account from reaching an inbound added later.
//
// An empty tag is an inbound that is not carried (see CarriedNames). An
// account that was only on such inbounds is not limited — limited to nothing
// it would reach nothing — and its row says so.
//
// An empty mine is an account on none of them (a PasarGuard account whose
// groups reach only WireGuard): it is kept off every one.
func LimitToInbounds(c *Client, mine, all []string) {
	if len(mine) == 0 {
		c.InboundsOff = offAll(all)
		return
	}
	tags, uncarried := limitTags(mine, all)
	c.InboundTags = tags
	c.OnlyUncarried = c.OnlyUncarried || uncarried
}

func offAll(all []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range all {
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// LimitToEndpoints is LimitToInbounds for the account's WireGuard endpoints.
func LimitToEndpoints(c *Client, mine, all []string) {
	c.EndpointTags, _ = limitTags(mine, all)
	if len(c.EndpointTags) > 0 {
		return
	}
	for _, t := range mine {
		if t != "" {
			return // on every one of them
		}
	}
	c.EndpointsOff = offAll(all)
}

func limitTags(mine, all []string) (tags []string, onlyUncarried bool) {
	have := map[string]bool{}
	for _, t := range mine {
		if t != "" && !have[t] {
			have[t] = true
			tags = append(tags, t)
		}
	}
	if len(tags) == 0 {
		return nil, len(mine) > 0
	}
	for _, t := range all {
		if !have[t] {
			sort.Strings(tags)
			return tags, false
		}
	}
	return nil, false
}

// ClientItem turns a Client into the bundle item that will be POSTed to
// /api/users. namer is the shared namespace for this bundle's client names.
func ClientItem(c Client, namer *normalize.Namer) bundle.Item {
	res := namer.Name(c.Name, "client-"+c.SourceID)

	cred := map[string]string{}
	setStr(cred, "uuid", c.UUID)
	setStr(cred, "password", c.Password)
	setStr(cred, "flow", c.Flow)
	setStr(cred, "method", c.Method)
	setStr(cred, "wgPrivateKey", c.WGPrivateKey)
	credRaw, _ := json.Marshal(cred)

	payload := map[string]any{
		"name":       res.Name,
		"enable":     c.Enable,
		"config":     json.RawMessage(credRaw),
		"desc":       c.Desc,
		"remark":     c.Remark,
		"group":      c.Group,
		"volume":     c.Volume,
		"expiry":     c.Expiry,
		"duration":   c.Duration,
		"up":         c.Up,
		"down":       c.Down,
		"speedLimit": c.SpeedLimit,
		"ipLimit":    c.IPLimit,
		"autoReset":  c.AutoReset,
		"resetDays":  c.ResetDays,
		"onlineAt":   c.OnlineAt,
	}
	if len(c.Contact) > 0 {
		payload["contact"] = c.Contact
	}
	if c.ResetPeriod != "" {
		payload["resetPeriod"] = c.ResetPeriod
		payload["resetStartDay"] = c.ResetStartDay
		// The rolling length means nothing beside a period, and a stored one
		// would only be there to be misread later.
		payload["resetDays"] = 0
	}
	if c.ActivatedAt > 0 {
		payload["activatedAt"] = c.ActivatedAt
	}
	if c.NextReset > 0 && c.AutoReset {
		payload["nextReset"] = c.NextReset
	}
	if c.SubID != "" {
		payload["subId"] = c.SubID
	}
	if len(c.TemplateItems) == 0 {
		// No template selected means the account goes everywhere, which is what
		// an operator migrating a whole panel wants and what NX's create
		// route does by default.
		payload["allTemplates"] = true
	} else {
		payload["allTemplates"] = false
		payload["templateIds"] = []uint{}
	}
	filterNote := ""
	filter := map[string]any{}
	for _, sec := range []struct {
		key, what string
		tags      []string
	}{{"inbounds", "inbounds", c.InboundTags}, {"endpoints", "WireGuard endpoints", c.EndpointTags}} {
		switch n := len(sec.tags); {
		case n > MaxFilterValues:
			filterNote = fmt.Sprintf("the old panel had this account on %d of its %s, more than the %d one config filter can name, so it is on every one of its template — narrow it in NX if that matters", n, sec.what, MaxFilterValues)
		case n > 0:
			// Keyed by tag, which is what the panel stores and matches (a tag
			// is unique there). A tag naming something the template does not
			// carry is ignored by the panel, never refused.
			filter[sec.key] = []map[string]any{{"field": "tag", "op": "in", "values": sec.tags}}
		}
	}
	if n := len(c.InboundsOff); n > 0 && n <= MaxFilterValues && len(c.InboundTags) == 0 {
		filter["inbounds"] = []map[string]any{{"field": "tag", "op": "notIn", "values": c.InboundsOff}}
	}
	if n := len(c.EndpointsOff); n > 0 && n <= MaxFilterValues && len(c.EndpointTags) == 0 {
		filter["endpoints"] = []map[string]any{{"field": "tag", "op": "notIn", "values": c.EndpointsOff}}
	}
	if len(filter) > 0 {
		payload["configFilter"] = filter
	}
	raw, _ := json.Marshal(payload)

	it := bundle.Item{
		ID:         "client:" + c.SourceID,
		Kind:       bundle.KindClient,
		Name:       res.Name,
		SourceName: c.Name,
		Payload:    raw,
	}
	if c.Group != "" {
		it.Group = []string{c.Group}
	}
	if len(c.TemplateItems) > 0 {
		it.IDRefs = map[string][]string{"templateIds": c.TemplateItems}
	}
	if c.OwnerItem != "" {
		it.IDRef = map[string]string{"adminId": c.OwnerItem}
	}

	// The review table.
	it.Set("quota", bytesLabel(c.Volume))
	it.Set("used", bytesLabel(c.Up+c.Down))
	it.Set("expires", expiryLabel(c))
	it.Set("enabled", yesNo(c.Enable))
	if c.UUID != "" {
		it.Set("uuid", c.UUID)
	}
	if c.SubURL != "" {
		it.Set("old link", c.SubURL)
	}
	if c.SubID != "" {
		it.Set("sub id", c.SubID)
	}

	if n := len(c.InboundTags); n > 0 && n <= MaxFilterValues {
		it.Set("limited to", strings.Join(c.InboundTags, ", "))
	}
	if n := len(c.EndpointTags); n > 0 && n <= MaxFilterValues {
		it.Set("wireguard limited to", strings.Join(c.EndpointTags, ", "))
	}
	if n := len(c.EndpointsOff); n > 0 && n <= MaxFilterValues && len(c.EndpointTags) == 0 {
		it.Set("wireguard", "none")
	}
	if n := len(c.InboundsOff); n > 0 && n <= MaxFilterValues && len(c.InboundTags) == 0 {
		it.Set("inbounds", "none (WireGuard only)")
	}
	if res.Changed {
		it.AddNote("%s", res.Note)
	}
	if filterNote != "" {
		it.AddNote("%s", filterNote)
	}
	if c.OnlyUncarried {
		it.AddNote("the old panel had this account only on inbounds that cannot come to NX, so it is on every inbound of its template here — limit it in NX if it should reach fewer")
	}
	if len(c.Conflicts) > 0 {
		it.AddNote("NX keeps one credential set per account; these protocols had their own and will change for this user: %s",
			strings.Join(c.Conflicts, ", "))
	}
	if c.SingleCounter && (c.Down > 0) {
		it.AddNote("the old panel kept one traffic total, not upload and download separately — all %s is recorded as download",
			bytesLabel(c.Down))
	}
	if c.SubID == "" {
		it.AddNote("no subscription token came across, so this user gets a new link")
	}
	return it
}

func setStr(m map[string]string, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func expiryLabel(c Client) string {
	switch {
	case c.Duration > 0 && c.ActivatedAt == 0:
		return fmt.Sprintf("%d days, starts on first use", c.Duration/86400)
	case c.Expiry == 0:
		return "never"
	default:
		return time.Unix(c.Expiry, 0).UTC().Format("2006-01-02")
	}
}

// bytesLabel renders a byte count the way an operator reads it, and says
// "unlimited" for the zero that means exactly that everywhere in NX.
func bytesLabel(n int64) string {
	if n == 0 {
		return "unlimited"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// GBToBytes converts a gigabyte figure (Hiddify keeps quotas that way) into
// bytes, rounding to the nearest byte.
func GBToBytes(gb float64) int64 {
	if gb <= 0 {
		return 0
	}
	return int64(gb * 1024 * 1024 * 1024)
}

// MillisToUnix converts a millisecond timestamp (3x-ui's expiryTime) into unix
// seconds. A negative value is 3x-ui's "this many milliseconds after first
// use", which the caller handles instead.
func MillisToUnix(ms int64) int64 {
	if ms <= 0 {
		return 0
	}
	return ms / 1000
}

// ApplyResetStrategy maps a source panel's reset strategy onto NX's cycle.
//
// Every panel this tool reads spells the cycle as a strategy — day / week /
// month / year, however each one capitalises it — and until NX had calendar
// periods the only thing to write was a day count, so "month" became 30 days.
// That is a silent change to what the customer bought: the reset day walks
// about five days a year, and by the second year it is in the middle of a
// different billing month. The mapping is now exact, and only "day" is still a
// rolling cycle, because a day is a day in every calendar.
//
// The anchor is the day the account's cycle should turn on. A source that does
// not say gets the 1st, which is what "monthly" means to the operator selling
// it; an importer that knows better (a stored anchor, or the day the last reset
// happened) passes it.
func ApplyResetStrategy(c *Client, strategy string, anchorDay int) {
	if anchorDay < 1 || anchorDay > 31 {
		anchorDay = 1
	}
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "day", "daily":
		c.AutoReset, c.ResetDays = true, 1
	case "week", "weekly":
		c.AutoReset, c.ResetPeriod, c.ResetStartDay = true, "weekly", 0
	case "month", "monthly", "month_rolling":
		c.AutoReset, c.ResetPeriod, c.ResetStartDay = true, "monthly", anchorDay
	case "year", "yearly", "annual":
		c.AutoReset, c.ResetPeriod, c.ResetStartDay = true, "yearly", anchorDay
	}
}

// SetContact records one of the customer's details, ignoring an empty value so
// a source that simply has no email does not write the key. The standard keys
// are model.ContactTelegramID / Email / Phone on the panel side; this package
// deliberately does not import the panel, so they are spelled here.
func SetContact(c *Client, key, value string) {
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return
	}
	if c.Contact == nil {
		c.Contact = map[string]string{}
	}
	c.Contact[key] = value
}

// The keys the panel itself reads (filters, CSV columns, the user form).
const (
	ContactTelegramID = "telegram_id"
	ContactEmail      = "email"
	ContactPhone      = "phone"
)
