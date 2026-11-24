package xraysql

import (
	"testing"

	"github.com/nx-panel/nx-migrate/internal/bundle"
	"github.com/nx-panel/nx-migrate/internal/sublink"
)

func links(t *testing.T, settings map[string]string, p Panel) map[string]sublink.Old {
	t.Helper()
	b := &bundle.Bundle{}
	SubLinks(b, settings, p)
	out := map[string]sublink.Old{}
	for _, it := range b.Items {
		o, err := sublink.Decode(it)
		if err != nil {
			t.Fatal(err)
		}
		out[o.Label] = o
	}
	return out
}

var (
	threeXUI = Panel{Name: "3x-ui", SubOnByDefault: true}
	xui      = Panel{Name: "x-ui", JSONAlwaysOn: true}
)

// 3x-ui v3 writes a random path for each of its three subscription paths on
// a fresh install (web/service/setting.go ResetSettings), on port 2096.
func TestThreeXUIRandomPaths(t *testing.T) {
	got := links(t, map[string]string{
		"subDomain": "Sub.Old.com", "subCertFile": "/c", "subKeyFile": "/k",
		"subPath": "/k3j9x0q2w8e7r6t5/", "subJsonPath": "/a1s2d3f4g5h6j7k8/", "subJsonEnable": "true",
		"subClashPath": "/z9x8c7v6b5n4m3l2/", "subClashEnable": "true",
	}, threeXUI)
	want := map[string]sublink.Old{
		"subscription":       {Scheme: "https", Host: "sub.old.com", Port: 2096, Path: "/k3j9x0q2w8e7r6t5", Label: "subscription"},
		"JSON subscription":  {Scheme: "https", Host: "sub.old.com", Port: 2096, Path: "/a1s2d3f4g5h6j7k8", Label: "JSON subscription", Format: "xray"},
		"Clash subscription": {Scheme: "https", Host: "sub.old.com", Port: 2096, Path: "/z9x8c7v6b5n4m3l2", Label: "Clash subscription", Format: "clash"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %+v, want %+v", k, got[k], w)
		}
	}
}

// A reverse-proxied 3x-ui publishes subURI; that is the link customers hold.
// JSON and Clash are off unless switched on, and nothing is published when
// the subscription server is off.
func TestThreeXUIDefaultsAndURI(t *testing.T) {
	got := links(t, map[string]string{"subURI": "https://cdn.old.com/s/"}, threeXUI)
	if len(got) != 1 || got["subscription"].Host != "cdn.old.com" || got["subscription"].Path != "/s" {
		t.Fatalf("got %v", got)
	}
	hostless := links(t, map[string]string{}, threeXUI)["subscription"]
	if hostless.Host != "" || hostless.Port != 2096 || hostless.Path != "/sub" || hostless.Scheme != "http" {
		t.Errorf("defaults = %+v", hostless)
	}
	if got := links(t, map[string]string{"subEnable": "false"}, threeXUI); len(got) != 0 {
		t.Errorf("subscription server off: %v", got)
	}
}

// alireza0's x-ui serves its JSON path whenever the subscription server is
// on, which it is not by default.
func TestXUIJSONAlwaysOnAndOffByDefault(t *testing.T) {
	if got := links(t, map[string]string{}, xui); len(got) != 0 {
		t.Fatalf("x-ui with no subEnable row published %v", got)
	}
	got := links(t, map[string]string{"subEnable": "true", "subDomain": "x.old.com"}, xui)
	if len(got) != 2 || got["JSON subscription"].Path != "/json" || got["JSON subscription"].Format != "xray" {
		t.Fatalf("got %v", got)
	}
}
