package web

import (
	"strings"
	"testing"

	"github.com/nx-panel/nx-migrate/internal/bundle"
	"github.com/nx-panel/nx-migrate/internal/target"
)

// The panel caps accounts and nodes, and an import creates no node, so the
// only warning is about accounts — never about the inbounds, outbounds,
// endpoints or admins the licence stopped counting.
func TestLicenceWarningsCountAccountsOnly(t *testing.T) {
	pre := target.Preflight{LicenceReadable: true, Licence: []target.ResourceUsage{
		{Resource: "user", Used: 45, Max: 50},
		{Resource: "inbound", Used: 9, Max: 10},
	}}
	got := licenceWarnings(pre, map[bundle.Kind]int{bundle.KindClient: 6, bundle.KindInbound: 5})
	if len(got) != 1 || !strings.Contains(got[0], "room for 5 more user(s) but 6") {
		t.Errorf("warnings = %v", got)
	}
	if got := licenceWarnings(pre, map[bundle.Kind]int{bundle.KindClient: 5, bundle.KindInbound: 50}); got != nil {
		t.Errorf("within the cap: %v", got)
	}
	if got := licenceWarnings(target.Preflight{}, map[bundle.Kind]int{bundle.KindInbound: 3}); got != nil {
		t.Errorf("no accounts selected, nothing to warn about: %v", got)
	}
	if got := licenceWarnings(target.Preflight{}, map[bundle.Kind]int{bundle.KindClient: 3}); len(got) != 1 {
		t.Errorf("an unreadable licence with accounts selected: %v", got)
	}
}
