// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/fingerprint"
)

type pluginData struct {
	ns  map[string]string
	top []string
}

func (d pluginData) RESTNamespaces() map[string]string { return d.ns }
func (d pluginData) TopPlugins() []string              { return d.top }

// testPluginData knows three of the fixture's five plugin namespaces and
// lists 20 popular slugs, four of which the fixture has.
func testPluginData() pluginData {
	d := pluginData{ns: map[string]string{
		"contact-form-7": "contact-form-7",
		"yoast":          "wordpress-seo",
		"wc":             "woocommerce",
	}}
	for i := range 16 {
		d.top = append(d.top, fmt.Sprintf("absent-%02d", i))
	}
	d.top = slices.Insert(d.top, 3, "akismet", "jetpack", "elementor", "wordfence")
	return d
}

const wpHome = `<meta name="generator" content="WordPress 6.9.3" />
<link href="/wp-content/plugins/contact-form-7/a.css?ver=5.9.3">`

// wpSite serves a WordPress site with a REST index and a readme.txt for
// four plugins, recording peak requests in flight. catchAll makes every
// path answer 200 with body.
type wpSite struct {
	*httptest.Server
	inflight, peak atomic.Int64
	mu             sync.Mutex
	paths          []string
}

func newWPSite(t *testing.T, catchAll string) *wpSite {
	t.Helper()
	readmes := map[string]string{
		"akismet": "1.0", "jetpack": "13.1", "elementor": "3.20.0", "wordfence": "7.11.0", "contact-form-7": "5.9.3",
	}
	s := &wpSite{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := s.inflight.Add(1)
		defer s.inflight.Add(-1)
		for p := s.peak.Load(); n > p && !s.peak.CompareAndSwap(p, n); p = s.peak.Load() {
		}
		s.mu.Lock()
		s.paths = append(s.paths, r.URL.Path)
		s.mu.Unlock()
		time.Sleep(time.Millisecond) // long enough for requests to overlap if they may
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(wpHome))
			return
		}
		if catchAll != "" {
			_, _ = w.Write([]byte(catchAll))
			return
		}
		if r.URL.Path == "/wp-json/" {
			_, _ = w.Write([]byte(`{"name":"x","namespaces":["oembed\/1.0","wp\/v2","contact-form-7\/v1","yoast\/v1","wc\/v3","acme-internal\/v1","custom\/v2"],"routes":{}}`))
			return
		}
		if slug, ok := strings.CutPrefix(r.URL.Path, "/wp-content/plugins/"); ok {
			if v, ok := readmes[strings.TrimSuffix(slug, "/readme.txt")]; ok && strings.HasSuffix(slug, "/readme.txt") {
				fmt.Fprintf(w, "=== %s ===\nContributors: someone\nStable tag: %s\n\nA plugin.\n", slug, v)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *wpSite) readmeRequests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, p := range s.paths {
		if strings.HasSuffix(p, "/readme.txt") {
			n++
		}
	}
	return n
}

func scanWP(t *testing.T, site *wpSite, opts Options) *Result {
	t.Helper()
	opts.HTTPClient = site.Client()
	if opts.PluginData == nil {
		opts.PluginData = testPluginData()
	}
	res, err := New([]*Check{mustParse(t, envCheck)}, opts).Scan(context.Background(), site.URL, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func components(fp fingerprint.Result) map[string]fingerprint.Component {
	m := map[string]fingerprint.Component{}
	for _, c := range fp.Components {
		m[c.Slug] = c
	}
	return m
}

func TestDiscoverPassive(t *testing.T) {
	site := newWPSite(t, "")
	res := scanWP(t, site, Options{})
	got := components(res.Fingerprint)
	if len(got) != 3 {
		t.Fatalf("components %+v", res.Fingerprint.Components)
	}
	if c := got["contact-form-7"]; c.FoundBy != "asset,rest" || c.Confidence != "high" || c.Version != "5.9.3" {
		t.Errorf("contact-form-7 %+v", c)
	}
	for _, slug := range []string{"wordpress-seo", "woocommerce"} {
		if c := got[slug]; c.FoundBy != "rest" || c.Confidence != "high" {
			t.Errorf("%s %+v", slug, c)
		}
	}
	// Passive mode probes no readme beyond the version lookups for what
	// it found.
	if n := site.readmeRequests(); n != 3 {
		t.Errorf("%d readme requests, want 3 (one version lookup per plugin)", n)
	}
	if !res.Complete || len(res.Warnings) != 0 {
		t.Errorf("complete %v, warnings %q", res.Complete, res.Warnings)
	}
}

func TestDiscoverDeep(t *testing.T) {
	site := newWPSite(t, "")
	res := scanWP(t, site, Options{Plugins: PluginsDeep})
	got := components(res.Fingerprint)
	if len(got) != 7 {
		t.Fatalf("components %+v", res.Fingerprint.Components)
	}
	for slug, v := range map[string]string{"akismet": "1.0", "jetpack": "13.1", "elementor": "3.20.0", "wordfence": "7.11.0"} {
		if c := got[slug]; c.FoundBy != "readme" || c.Confidence != "high" || c.Version != v || c.Source != "readme" {
			t.Errorf("%s %+v", slug, c)
		}
	}
	// One request per popular slug and the baseline; found readmes are
	// not fetched again for their version.
	if n := site.readmeRequests(); n != 20+1+3 {
		t.Errorf("%d readme requests, want 24", n)
	}
	if !res.Complete {
		t.Errorf("stopped by %q: %q", res.StoppedBy, res.Warnings)
	}
}

func TestDiscoverCatchAll(t *testing.T) {
	for name, body := range map[string]string{
		"readme everywhere": "=== Some Plugin ===\nStable tag: 1.0\n",
		"page everywhere":   "<html><body>Welcome</body></html>",
	} {
		t.Run(name, func(t *testing.T) {
			res := scanWP(t, newWPSite(t, body), Options{Plugins: PluginsDeep})
			for _, c := range res.Fingerprint.Components {
				if c.FoundBy.Has("readme") || c.FoundBy.Has("rest") {
					t.Errorf("fake plugin %+v", c)
				}
			}
			if name == "readme everywhere" && !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "answers every readme.txt path") }) {
				t.Errorf("warnings %q", res.Warnings)
			}
		})
	}
}

func TestDiscoverBudget(t *testing.T) {
	site := newWPSite(t, "")
	res := scanWP(t, site, Options{Plugins: PluginsDeep, RequestBudget: 10})
	want := "plugin discovery stopped at its budget of 10 requests: results are partial; raise --request-budget to probe more plugins"
	if !slices.Contains(res.Warnings, want) {
		t.Errorf("warnings %q", res.Warnings)
	}
	if res.Complete || res.StoppedBy != "budget" {
		t.Errorf("complete %v, stopped by %q", res.Complete, res.StoppedBy)
	}
	// /wp-json/, the baseline and 8 readmes; then version lookups for the
	// three plugins the REST index found.
	if n := site.readmeRequests(); n != 1+8+3 {
		t.Errorf("%d readme requests, want 12", n)
	}
}

func TestDiscoverConcurrencyOne(t *testing.T) {
	site := newWPSite(t, "")
	scanWP(t, site, Options{Plugins: PluginsDeep, Concurrency: 1})
	if p := site.peak.Load(); p != 1 {
		t.Errorf("peak %d requests in flight with -c 1", p)
	}
}

type slugAdvisor struct{ slugs []string }

func (slugAdvisor) Advise(context.Context, *url.URL, fingerprint.Result) ([]Finding, []string) {
	return nil, nil
}

func (a slugAdvisor) PluginSlugs(context.Context) []string { return a.slugs }

func TestDiscoverAdvisorSlugs(t *testing.T) {
	site := newWPSite(t, "")
	d := testPluginData()
	d.top = d.top[:3] // none of the fixture's readmes
	adv := Filtered(slugAdvisor{[]string{"jetpack", "../etc", "jetpack"}}, Selector{})
	res := scanWP(t, site, Options{Plugins: PluginsDeep, PluginData: d, Advisor: adv})
	if c := components(res.Fingerprint)["jetpack"]; c.FoundBy != "readme" {
		t.Errorf("jetpack %+v", c)
	}
	site.mu.Lock()
	defer site.mu.Unlock()
	for _, p := range site.paths {
		if strings.Contains(p, "..") || strings.Contains(p, "etc") {
			t.Errorf("probed %s", p)
		}
	}
}

func TestParsePluginMode(t *testing.T) {
	for in, want := range map[string]PluginMode{"": PluginsPassive, "passive": PluginsPassive, "Deep": PluginsDeep} {
		if got, err := ParsePluginMode(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	if _, err := ParsePluginMode("loud"); err == nil || err.Error() != `unknown plugin discovery mode "loud": want passive or deep` {
		t.Errorf("loud: %v", err)
	}
}

// A blocked or failing home page skips the readme probes: they would
// only measure the block page.
func TestDiscoverDeepSkippedWhenHomeFails(t *testing.T) {
	mux := http.NewServeMux()
	var readmes atomic.Int64
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(wpHome))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// contact-form-7 is on the home page, so its version lookup still runs.
		if strings.HasSuffix(r.URL.Path, "/readme.txt") && !strings.Contains(r.URL.Path, "/contact-form-7/") {
			readmes.Add(1)
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := New([]*Check{mustParse(t, envCheck)}, Options{HTTPClient: srv.Client(), Plugins: PluginsDeep, PluginData: testPluginData()}).
		Scan(context.Background(), srv.URL, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if n := readmes.Load(); n != 0 {
		t.Errorf("%d readme probes behind a failing home page", n)
	}
	if !slices.Contains(res.Warnings, "plugin discovery skipped readme probes because the home page was blocked or failed") {
		t.Errorf("warnings %q", res.Warnings)
	}
	if res.StoppedBy != "home-status" {
		t.Errorf("stopped by %q", res.StoppedBy)
	}
}

// With the default budget an advisor that knows more plugins than fit is
// cut to the budget, and the scan stays complete.
func TestDiscoverDefaultBudgetFitsAdvisorSlugs(t *testing.T) {
	site := newWPSite(t, "")
	var many []string
	for i := range DefaultRequestBudget {
		many = append(many, fmt.Sprintf("advised-%04d", i))
	}
	res := scanWP(t, site, Options{Plugins: PluginsDeep, Advisor: slugAdvisor{many}})
	if !res.Complete || res.StoppedBy != "" {
		t.Errorf("complete %v, stopped by %q, warnings %q", res.Complete, res.StoppedBy, res.Warnings)
	}
	// 20 popular slugs; 2000 - 2 - 20 advisory slugs fit.
	want := fmt.Sprintf("plugin discovery probed %d of %d plugins with known advisories; raise --request-budget to probe the rest",
		DefaultRequestBudget-22, DefaultRequestBudget)
	if !slices.Contains(res.Warnings, want) {
		t.Errorf("warnings %q, want %q", res.Warnings, want)
	}
	// The probes plus version lookups for the three REST plugins.
	if n := site.readmeRequests(); n != DefaultRequestBudget-1+3 {
		t.Errorf("%d readme requests, want %d", n, DefaultRequestBudget-1+3)
	}
}
