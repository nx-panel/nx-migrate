package target

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Whether the run switches the nodes off by default follows the accounts the
// panel already serves: a node switched off in NX is emptied, so on a live
// panel the pause is an outage, and it is the default only where nobody is
// served yet — or not at all when that cannot be read.
func TestPauseByDefaultFollowsTheAccounts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		users     any // the users list's body, nil for a 403
		licence   int64
		wantUsers int64
		known     bool
		pause     bool
	}{
		{"empty panel", []any{}, 0, 0, true, true},
		{"live panel", []any{map[string]any{"name": "a"}, map[string]any{"name": "b"}}, 2, 2, true, false},
		{"list refused, licence says", nil, 3, 3, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			reply := func(v any) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(v) }
			}
			mux.HandleFunc("GET /api/me", reply(map[string]any{"username": "sudo", "role": "sudo"}))
			mux.HandleFunc("GET /api/license", reply(map[string]any{"usage": []map[string]any{
				{"resource": "user", "used": tc.licence, "max": 50},
			}}))
			mux.HandleFunc("GET /api/users", func(w http.ResponseWriter, r *http.Request) {
				if tc.users == nil {
					http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
					return
				}
				_ = json.NewEncoder(w).Encode(tc.users)
			})
			ts := httptest.NewServer(mux)
			defer ts.Close()

			c, err := Connect(context.Background(), Options{BaseURL: ts.URL, Token: "t"})
			if err != nil {
				t.Fatal(err)
			}
			p, err := c.Check(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if p.Users != tc.wantUsers || p.UsersKnown != tc.known || p.PauseByDefault() != tc.pause {
				t.Errorf("users = %d known = %v pause = %v, want %d %v %v",
					p.Users, p.UsersKnown, p.PauseByDefault(), tc.wantUsers, tc.known, tc.pause)
			}
		})
	}

	if (Preflight{}).PauseByDefault() {
		t.Error("an unreadable panel must not be paused by default")
	}
}
