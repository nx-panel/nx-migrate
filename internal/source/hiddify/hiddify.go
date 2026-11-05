// Package hiddify reads a Hiddify Manager installation over its v2 admin API.
//
// Hiddify is the easiest of these panels to map and the hardest to keep links
// for. Easy, because one account has exactly one uuid and every protocol uses
// it — there is no per-protocol credential to collapse. Hard, because its
// subscription URL is `/{proxy_path}/{uuid}/sub/`: three segments, one of them
// an install-wide secret, so no amount of care on NX's side reproduces it.
// Those customers get new links, and the review says so per account.
package hiddify

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nx-panel/nx-migrate/internal/bundle"
	"github.com/nx-panel/nx-migrate/internal/convert"
	"github.com/nx-panel/nx-migrate/internal/httpx"
	"github.com/nx-panel/nx-migrate/internal/normalize"
	"github.com/nx-panel/nx-migrate/internal/source"
)

func init() {
	source.Register(source.Descriptor{
		ID:             "hiddify",
		Label:          "Hiddify Manager",
		Channels:       []source.Channel{source.ChannelAPI},
		Auth:           []source.AuthMode{source.AuthToken},
		NeedsProxyPath: true,
		Hint:           "Give the panel address, the secret path segment from your admin URL, and an admin UUID as the API key.",
	}, reader{})
}

type reader struct{}

type hiddifyUser struct {
	UUID         string   `json:"uuid"`
	Name         string   `json:"name"`
	UsageLimitGB *float64 `json:"usage_limit_GB"`
	PackageDays  *int     `json:"package_days"`
	Mode         string   `json:"mode"`
	LastOnline   string   `json:"last_online"`
	StartDate    string   `json:"start_date"`
	CurrentUsage *float64 `json:"current_usage_GB"`
	Comment      string   `json:"comment"`
	AddedBy      string   `json:"added_by_uuid"`
	Enable       *bool    `json:"enable"`
	IsActive     *bool    `json:"is_active"`
	// The person, and what Hiddify keeps about them beside the plan.
	TelegramID    *int64 `json:"telegram_id"`
	Lang          string `json:"lang"`
	LastResetTime string `json:"last_reset_time"`
	// v14: the outbound all of this account's traffic leaves through.
	PreferredOutbound string `json:"preferred_outbound_slug"`
}

type hiddifyAdmin struct {
	UUID     string `json:"uuid"`
	Name     string `json:"name"`
	Mode     string `json:"mode"`
	Comment  string `json:"comment"`
	MaxUsers *int   `json:"max_users"`
	// v10.30 / v14: the agent's other limits.
	MaxActiveUsers *int     `json:"max_active_users"`
	MaxOnlineUsers *int     `json:"max_online_users"`
	MaxTotalGB     *float64 `json:"max_total_usage_GB"`
}

func (reader) Read(ctx context.Context, opt source.Options) (*bundle.Bundle, error) {
	if opt.Token == "" {
		return nil, fmt.Errorf("Hiddify needs an API key — an admin's UUID, sent as the Hiddify-API-Key header")
	}
	proxyPath := strings.Trim(strings.TrimSpace(opt.ProxyKey), "/")
	if proxyPath == "" {
		return nil, fmt.Errorf("Hiddify needs the secret path segment from your admin URL (the part between the host and /admin)")
	}
	c, err := httpx.New(opt.BaseURL, opt.Insecure)
	if err != nil {
		return nil, err
	}
	c.Headers["Hiddify-API-Key"] = opt.Token
	base := "/" + proxyPath + "/api/v2/admin"

	b := &bundle.Bundle{Source: bundle.SourceInfo{Panel: "Hiddify Manager", Origin: c.Base}}
	b.Note("Hiddify's subscription link is /<secret path>/<uuid>/sub/ — three segments, one of them an install-wide secret. NX resolves a single-segment token, so every account here gets a new link and customers have to be re-sent it.")
	b.Note("Hiddify manages its own inbounds, domains and routing from its config pages rather than storing a sing-box document, so nothing in those pages is offered here — build the inbounds in NX first.")

	admins := readAdmins(ctx, c, base, b)
	if err := readUsers(ctx, c, base, b, admins); err != nil {
		return nil, err
	}
	return b, nil
}

func readAdmins(ctx context.Context, c *httpx.Client, base string, b *bundle.Bundle) map[string]string {
	out := map[string]string{}
	var admins []hiddifyAdmin
	if err := c.Get(ctx, base+"/admin_user/", &admins); err != nil {
		b.Note("the admin list could not be read (%v); accounts arrive without an owner", err)
		return out
	}
	namer := normalize.NewNamer()
	for _, a := range admins {
		if a.Name == "" {
			continue
		}
		res := namer.Name(a.Name, "admin-"+shortUUID(a.UUID))
		// Hiddify's three modes map onto NX's two importable roles: an
		// agent sells, so it is a reseller; the rest operate the panel.
		role := "admin"
		if strings.EqualFold(a.Mode, "agent") {
			role = "resale"
		}
		pw := convert.RandomPassword()
		payload := map[string]any{"username": res.Name, "password": pw, "role": role}
		if role == "resale" && a.MaxUsers != nil && *a.MaxUsers > 0 {
			payload["userLimit"] = *a.MaxUsers
		}
		var limits []string
		if a.MaxActiveUsers != nil && *a.MaxActiveUsers > 0 {
			limits = append(limits, fmt.Sprintf("%d active accounts", *a.MaxActiveUsers))
		}
		if a.MaxOnlineUsers != nil && *a.MaxOnlineUsers > 0 {
			limits = append(limits, fmt.Sprintf("%d accounts online in a day", *a.MaxOnlineUsers))
		}
		if a.MaxTotalGB != nil && *a.MaxTotalGB > 0 {
			limits = append(limits, fmt.Sprintf("%g GB across its accounts", *a.MaxTotalGB))
		}
		body, _ := json.Marshal(payload)
		it := bundle.Item{
			ID: "admin:" + a.UUID, Kind: bundle.KindAdmin,
			Name: res.Name, SourceName: a.Name, Payload: body,
		}
		it.Set("role", role)
		it.Set("hiddify mode", a.Mode)
		it.Set("new password", pw)
		if res.Changed {
			it.AddNote("%s", res.Note)
		}
		it.AddNote("password hashes cannot move between panels: this admin arrives with the generated password shown here — write it down, it is not stored")
		if len(limits) > 0 {
			// Hiddify's total traffic cap only stops new accounts being made
			// or switched on; NX's reseller volume switches the accounts off,
			// so carrying it would cut customers off that Hiddify kept serving.
			it.Set("hiddify limits", strings.Join(limits, ", "))
			it.AddNote("Hiddify also limited this admin to %s; NX has no equivalent that behaves the same (its reseller traffic volume switches the accounts off rather than only refusing new ones), so these were not set — set a user limit or volume on the admin in NX if you want one", strings.Join(limits, ", "))
		}
		b.Add(it)
		out[a.UUID] = it.ID
	}
	return out
}

func readUsers(ctx context.Context, c *httpx.Client, base string, b *bundle.Bundle, admins map[string]string) error {
	var users []hiddifyUser
	if err := c.Get(ctx, base+"/user/", &users); err != nil {
		if httpx.Status(err) == 404 {
			b.Note("the panel reported no users for this API key")
			return nil
		}
		return fmt.Errorf("could not list accounts: %w", err)
	}
	names := normalize.NewNamer()
	for _, u := range users {
		b.Add(userItem(u, names, admins))
	}
	return nil
}

func userItem(u hiddifyUser, names *normalize.Namer, admins map[string]string) bundle.Item {
	c := convert.Client{
		SourceID: u.UUID,
		Name:     u.Name,
		Enable:   u.Enable == nil || *u.Enable,
		Desc:     u.Comment,
		// One uuid serves every protocol. Trojan and Shadowsocks use it as the
		// password, so it is carried into both fields rather than one.
		UUID:          u.UUID,
		Password:      u.UUID,
		SingleCounter: true,
	}
	if u.UsageLimitGB != nil {
		c.Volume = convert.GBToBytes(*u.UsageLimitGB)
	}
	if u.CurrentUsage != nil {
		c.Down = convert.GBToBytes(*u.CurrentUsage)
	}

	// package_days with no start_date is Hiddify's start-on-first-use, which is
	// exactly NX's Duration. With a start_date the clock has begun, so the
	// expiry is a real date and the start is kept.
	days := 0
	if u.PackageDays != nil {
		days = *u.PackageDays
	}
	if days > 0 {
		if start, ok := parseDate(u.StartDate); ok {
			c.Expiry = start.AddDate(0, 0, days).Unix()
			c.ActivatedAt = start.Unix()
		} else {
			c.Duration = int64(days) * 86400
		}
	}

	start, started := parseDate(u.StartDate)
	if n, ok := resetEvery[strings.ToLower(u.Mode)]; ok {
		// Hiddify's cycle is rolling and counted from the start date: usage
		// resets on every day that is a whole number of periods after it
		// ("monthly" is every 30 days, not the 1st). NX's rolling cycle is the
		// same thing once its first appointment is on Hiddify's next one; an
		// account that has not started opens it when its plan does.
		c.AutoReset, c.ResetDays = true, n
		if started {
			c.NextReset = nextRollingReset(start, n, time.Now())
		}
	}
	if strings.EqualFold(u.Mode, "disable") {
		c.Enable = false
	}
	if u.TelegramID != nil && *u.TelegramID != 0 {
		convert.SetContact(&c, convert.ContactTelegramID, strconv.FormatInt(*u.TelegramID, 10))
	}

	if id, ok := admins[u.AddedBy]; ok {
		c.OwnerItem = id
	}
	if t, ok := parseTime(u.LastOnline); ok {
		c.OnlineAt = t.Unix()
	}

	it := convert.ClientItem(c, names)
	it.Set("hiddify uuid", u.UUID)
	it.Set("mode", u.Mode)
	if u.IsActive != nil && !*u.IsActive {
		it.Set("active in hiddify", "no")
	}
	if u.Lang != "" {
		it.Set("language", u.Lang)
	}
	if t, ok := parseTime(u.LastResetTime); ok {
		it.Set("last reset", t.Format("2006-01-02"))
	}
	if u.PreferredOutbound != "" {
		it.Set("preferred outbound", u.PreferredOutbound)
		it.AddNote("in Hiddify all of this account's traffic left through the %q outbound; NX routes by the template, not by the account, so it now follows the template's rules", u.PreferredOutbound)
	}
	return it
}

// resetEvery is Hiddify's package_mode_dic: the length of each rolling cycle.
var resetEvery = map[string]int{"daily": 1, "weekly": 7, "monthly": 30}

// nextRollingReset is the first day after now that is a whole number of
// n-day periods from start, as Hiddify counts it.
func nextRollingReset(start time.Time, n int, now time.Time) int64 {
	period := time.Duration(n) * 24 * time.Hour
	if now.Before(start) {
		return start.Add(period).Unix()
	}
	k := now.Sub(start)/period + 1
	return start.Add(k * period).Unix()
}

func parseDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" {
		return time.Time{}, false
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			// Hiddify writes datetime.min for "never seen".
			if t.Year() < 1980 {
				return time.Time{}, false
			}
			return t, true
		}
	}
	return time.Time{}, false
}

func shortUUID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
