package hiddify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nx-panel/nx-migrate/internal/bundle"
	"github.com/nx-panel/nx-migrate/internal/source"
)

func read(t *testing.T) *bundle.Bundle {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /secret/api/v2/admin/admin_user/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"uuid": "aaaaaaaa-0000-0000-0000-000000000000", "name": "agent", "mode": "agent",
			"max_users": 10, "max_active_users": 8, "max_online_users": 0, "max_total_usage_GB": 500,
		}})
	})
	mux.HandleFunc("GET /secret/api/v2/admin/user/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"uuid": "11111111-1111-1111-1111-111111111111", "name": "monthly", "mode": "monthly",
				"package_days": 3650, "start_date": "2026-01-01", "usage_limit_GB": 50,
				"telegram_id": 12345, "lang": "fa", "last_reset_time": "2026-10-28 00:00:00",
				"preferred_outbound_slug": "warp", "added_by_uuid": "aaaaaaaa-0000-0000-0000-000000000000",
			},
			{"uuid": "22222222-2222-2222-2222-222222222222", "name": "fresh", "mode": "weekly", "package_days": 30},
			{"uuid": "33333333-3333-3333-3333-333333333333", "name": "off", "mode": "disable", "package_days": 30},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	b, err := reader{}.Read(context.Background(), source.Options{
		Channel: source.ChannelAPI, BaseURL: srv.URL, Token: "key", ProxyKey: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func item(t *testing.T, b *bundle.Bundle, id string) (bundle.Item, map[string]any) {
	t.Helper()
	for _, it := range b.Items {
		if it.ID == id {
			var p map[string]any
			_ = json.Unmarshal(it.Payload, &p)
			return it, p
		}
	}
	t.Fatalf("no item %q", id)
	return bundle.Item{}, nil
}

// Hiddify's cycle is a rolling one counted from the start date — "monthly" is
// every 30 days — and it used to arrive as a calendar month on the 1st.
func TestRollingCycleFromTheStartDate(t *testing.T) {
	b := read(t)
	it, p := item(t, b, "client:11111111-1111-1111-1111-111111111111")
	if p["autoReset"] != true || p["resetDays"] != float64(30) || p["resetPeriod"] != nil {
		t.Fatalf("cycle = autoReset %v resetDays %v resetPeriod %v", p["autoReset"], p["resetDays"], p["resetPeriod"])
	}
	next := time.Unix(int64(p["nextReset"].(float64)), 0).UTC()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if d := next.Sub(start).Hours() / 24; d != float64(int(d)) || int(d)%30 != 0 || !next.After(time.Now()) ||
		next.Sub(time.Now()) > 30*24*time.Hour {
		t.Errorf("next reset %s is not the next 30-day step from %s", next, start)
	}
	if c, _ := p["contact"].(map[string]any); c["telegram_id"] != "12345" {
		t.Errorf("contact = %v", p["contact"])
	}
	if it.Detail["language"] != "fa" || it.Detail["last reset"] != "2026-10-28" || it.Detail["preferred outbound"] != "warp" ||
		!strings.Contains(strings.Join(it.Notes, " "), `"warp" outbound`) {
		t.Errorf("detail = %v, notes = %v", it.Detail, it.Notes)
	}

	// Not started yet: the cycle opens with the plan, so no date is sent.
	_, p = item(t, b, "client:22222222-2222-2222-2222-222222222222")
	if p["resetDays"] != float64(7) || p["nextReset"] != nil {
		t.Errorf("fresh: resetDays %v nextReset %v", p["resetDays"], p["nextReset"])
	}
	if _, p = item(t, b, "client:33333333-3333-3333-3333-333333333333"); p["enable"] != false {
		t.Errorf("a disable-mode account arrived enabled")
	}
}

func TestAgentLimitsAreSaid(t *testing.T) {
	it, p := item(t, read(t), "admin:aaaaaaaa-0000-0000-0000-000000000000")
	if p["userLimit"] != float64(10) || p["volume"] != nil {
		t.Errorf("payload = %v", p)
	}
	if !strings.Contains(it.Detail["hiddify limits"], "8 active accounts, 500 GB") {
		t.Errorf("detail = %v", it.Detail)
	}
}
