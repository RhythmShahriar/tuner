// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package fingerprint

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

func TestEmbeddedData(t *testing.T) {
	d := Embedded()
	if n := len(d.TopPlugins()); n != 1500 {
		t.Errorf("%d top plugins, want 1500", n)
	}
	if top := d.TopPlugins(); top[0] != "elementor" || slices.Index(top, "contact-form-7") < 0 {
		t.Errorf("top plugins start %v", top[:3])
	}
	if n := len(d.RESTNamespaces()); n < 300 {
		t.Errorf("%d REST namespaces, want at least 300", n)
	}
	seen := map[string]bool{}
	for _, s := range d.TopPlugins() {
		if seen[s] {
			t.Errorf("duplicate top plugin %q", s)
		}
		seen[s] = true
	}
}

func TestLoadDataRejectsBadSlugs(t *testing.T) {
	fsys := fstest.MapFS{
		"data/rest-namespaces.json": {Data: []byte(`{"namespaces": {"acme": "acme"}}`)},
		"data/top-plugins.json":     {Data: []byte(`{"plugins": ["../../wp-config.php"]}`)},
	}
	if _, err := LoadData(fsys); err == nil || !strings.Contains(err.Error(), "not a plugin slug") {
		t.Errorf("err = %v", err)
	}
	fsys["data/top-plugins.json"] = &fstest.MapFile{Data: []byte(`{"plugins": ["acme-forms"]}`)}
	d, err := LoadData(fsys)
	if err != nil || d.RESTNamespaces()["acme"] != "acme" || d.TopPlugins()[0] != "acme-forms" {
		t.Errorf("pack data: %v %v", d, err)
	}
	if _, err := LoadData(fstest.MapFS{}); err == nil {
		t.Error("missing files must fail")
	}
}

func TestRESTNamespaces(t *testing.T) {
	// Cut mid-routes, as a big index is at the read limit.
	body := []byte(`{"name":"Site","namespaces":["oembed\/1.0","wp\/v2","contact-form-7\/v1"],"routes":{"\/":{"namesp`)
	if got := RESTNamespaces(body); !slices.Equal(got, []string{"oembed/1.0", "wp/v2", "contact-form-7/v1"}) {
		t.Errorf("got %q", got)
	}
	for _, bad := range []string{"<html>not json</html>", `{"namespaces": "x"}`, ""} {
		if got := RESTNamespaces([]byte(bad)); got != nil {
			t.Errorf("%q: got %q", bad, got)
		}
	}
}

type testData struct {
	ns  map[string]string
	top []string
}

func (d testData) RESTNamespaces() map[string]string { return d.ns }
func (d testData) TopPlugins() []string              { return d.top }

func TestPluginsFromREST(t *testing.T) {
	d := testData{
		ns:  map[string]string{"wc": "woocommerce", "wc/gla": "google-listings-and-ads", "yoast": "wordpress-seo"},
		top: []string{"jetpack", "akismet"},
	}
	got := PluginsFromREST(d, []string{"wp/v2", "oembed/1.0", "wc/v3", "wc/store/v1", "wc/gla", "yoast/v1", "jetpack/v4", "acme-internal/v1", "custom/v2", ""})
	want := []Component{
		{Type: "plugin", Slug: "woocommerce", FoundBy: "rest", Confidence: "high"},
		{Type: "plugin", Slug: "google-listings-and-ads", FoundBy: "rest", Confidence: "high"},
		{Type: "plugin", Slug: "wordpress-seo", FoundBy: "rest", Confidence: "high"},
		{Type: "plugin", Slug: "jetpack", FoundBy: "rest", Confidence: "low"}, // only its slug matches
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestIsReadme(t *testing.T) {
	for body, want := range map[string]bool{
		"=== Contact Form 7 ===\nContributors: takayukister\nStable tag: 5.9.3\n": true,
		"=== Akismet Anti-spam ===\r\nRequires at least: 5.8\r\n":                 true,
		"<html><title>Not found</title></html>":                                   false,
		"=== Heading only ===\n":                                                  false,
		"Stable tag: 1.0\n":                                                       false,
	} {
		if got := IsReadme([]byte(body)); got != want {
			t.Errorf("IsReadme(%q) = %v", body, got)
		}
	}
}

func TestAddComponent(t *testing.T) {
	var r Result
	r.AddComponent(Component{Type: "plugin", Slug: "jetpack", FoundBy: "rest", Confidence: "low"})
	r.AddComponent(Component{Type: "plugin", Slug: "jetpack", Version: "13.1", Source: "readme", FoundBy: "readme", Confidence: "high"})
	r.AddComponent(Component{Type: "theme", Slug: "jetpack", FoundBy: "asset", Confidence: "high"})
	if len(r.Components) != 2 {
		t.Fatalf("got %+v", r.Components)
	}
	c := r.Components[0]
	if c.FoundBy != "rest,readme" || c.Confidence != "high" || c.Version != "13.1" || c.Source != "readme" {
		t.Errorf("merged %+v", c)
	}
}
