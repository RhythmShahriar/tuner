// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/RhythmShahriar/tuner/fingerprint"
)

// At most this many plugins and themes get a version lookup per scan.
const maxComponents = 50

var (
	stableTag   = regexp.MustCompile(`(?mi)^[ \t]*Stable tag:[ \t]*([0-9][0-9A-Za-z.-]*)`)
	themeVer    = regexp.MustCompile(`(?mi)^[ \t*]*Version:[ \t]*([0-9][0-9A-Za-z.-]*)`)
	feedVersion = regexp.MustCompile(`<generator>https?://wordpress\.org/\?v=([0-9.]+)</generator>`)
)

// Uncacheable PHP endpoints. They still send X-Powered-By when a page cache
// (Cloudflare, LiteSpeed, Varnish) strips it from the home page. Paths that
// checks fetch anyway come first, so the probe usually costs nothing extra.
var (
	wpPHPProbes = []string{"/xmlrpc.php", "/wp-admin/admin-ajax.php", "/wp-login.php"}
	phpProbes   = []string{"/index.php"}
)

// probePHP looks for the PHP version on uncacheable endpoints when the home
// page didn't state it, stopping at the first that does. Responses go
// through the scan cache, so checks reuse them. It only reads fp, so it can
// run alongside resolveVersions; the caller stores what it finds.
//
// It runs only when the home page already pointed at PHP (WordPress, a
// session cookie), so a site with no PHP signal costs no extra requests.
// A PHP session cookie on a probed endpoint confirms PHP without a
// version: source is then "probe".
func (ss *session) probePHP(ctx context.Context, fp *fingerprint.Result) (version, build, source string) {
	if fp.PHP != "" || !fp.Has("php") {
		return "", "", ""
	}
	paths := phpProbes
	if fp.Has("wordpress") {
		paths = wpPHPProbes
	}
	for _, p := range paths {
		r, err := ss.get(ctx, "GET", p)
		if ctx.Err() != nil {
			break
		}
		if err != nil {
			continue
		}
		if v, b, header := fingerprint.PHPVersion(r.Header); v != "" {
			return v, b, header + " " + p
		}
		if source == "" && slices.ContainsFunc(r.Header.Values("Set-Cookie"), fingerprint.PHPCookie) {
			source = "probe"
		}
	}
	return "", "", source
}

// resolveVersions fills in WordPress, plugin and theme versions from the
// files that state them: /feed/ for core, readme.txt for plugins and
// style.css for themes. These beat ?ver= hints, which they replace.
func (ss *session) resolveVersions(ctx context.Context, fp *fingerprint.Result) {
	if !fp.Has("wordpress") {
		return
	}
	var wg sync.WaitGroup
	if fp.WordPress == "" {
		wg.Go(func() {
			if r, err := ss.get(ctx, "GET", "/feed/"); err == nil && r.Status == 200 {
				if m := feedVersion.FindSubmatch(r.Body); m != nil {
					fp.WordPress = string(m[1])
				}
			}
		})
	}
	for i := range fp.Components[:min(len(fp.Components), maxComponents)] {
		c := &fp.Components[i]
		if c.FoundBy.Has(fingerprint.FoundByReadme) {
			continue // discovery already read its readme
		}
		file, re, source := "/wp-content/plugins/"+c.Slug+"/readme.txt", stableTag, "readme"
		if c.Type == "theme" {
			file, re, source = "/wp-content/themes/"+c.Slug+"/style.css", themeVer, "style.css"
		}
		wg.Go(func() {
			r, err := ss.get(ctx, "GET", file)
			if err != nil || r.Status != 200 {
				return
			}
			if m := re.FindSubmatch(r.Body); m != nil {
				c.Version, c.Source = string(m[1]), source
			}
		})
	}
	wg.Wait()
}

// DefaultRequestBudget is how many requests plugin discovery may spend when
// Options.RequestBudget is 0. --plugins deep needs about 1,500; the rest
// leaves room for slugs with known advisories. With the default budget
// the advisory slugs are cut to fit, so a normal deep scan never runs out.
const DefaultRequestBudget = 2000

// ParsePluginMode reads a --plugins value in any case; "" is passive.
func ParsePluginMode(name string) (PluginMode, error) {
	switch m := PluginMode(strings.ToLower(strings.TrimSpace(name))); m {
	case "", PluginsPassive:
		return PluginsPassive, nil
	case PluginsDeep:
		return m, nil
	}
	return "", fmt.Errorf("unknown plugin discovery mode %q: want passive or deep", name)
}

// PluginLister is an Advisor that can name the plugin slugs it has
// advisories for. --plugins deep probes those after the popular ones, so a
// vulnerable but little-known plugin is not missed.
type PluginLister interface {
	PluginSlugs(ctx context.Context) []string
}

// discoverPlugins finds plugins the home page does not load. Passive (every
// profile) costs one request: the REST index at /wp-json/, whose namespaces
// name the plugins that register routes. Deep also asks for readme.txt of
// every popular plugin and of those the advisor knows advisories for.
//
// A readme only counts when it reads like one and differs from what the
// server sends for a plugin that cannot exist, so a site that answers 200
// to everything gains no plugins. Requests share the scan's pace and -c
// limit and stop at the request budget; budgetHit then reports it. When
// the home page was blocked or failed (homeFailed) the readme probes are
// skipped: they would only measure the block page.
func (ss *session) discoverPlugins(ctx context.Context, fp *fingerprint.Result, homeFailed bool) (warning string, budgetHit bool) {
	if !fp.Has("wordpress") {
		return "", false
	}
	data := ss.opts.PluginData
	if data == nil {
		data = fingerprint.Embedded()
	}
	budget := ss.opts.RequestBudget
	if budget <= 0 {
		budget = DefaultRequestBudget
	}
	var spent atomic.Int64
	spend := func() bool { return spent.Add(1) <= int64(budget) }
	stopped := func() string {
		return fmt.Sprintf("plugin discovery stopped at its budget of %d requests: results are partial; raise --request-budget to probe more plugins", budget)
	}

	if !spend() {
		return stopped(), true
	}
	if r, err := ss.get(ctx, "GET", "/wp-json/"); err == nil && r.Status == 200 && detectBlockPage(r) == nil {
		for _, c := range fingerprint.PluginsFromREST(data, fingerprint.RESTNamespaces(r.Body)) {
			fp.AddComponent(c)
		}
	}
	if ss.opts.Plugins != PluginsDeep || ctx.Err() != nil {
		return "", false
	}
	if homeFailed {
		return "plugin discovery skipped readme probes because the home page was blocked or failed", false
	}

	known := map[string]bool{}
	for _, c := range fp.Components {
		if c.Type == "plugin" {
			known[c.Slug] = true
		}
	}
	var slugs []string
	add := func(s string) {
		if !known[s] && fingerprint.ValidSlug(s) {
			known[s] = true
			slugs = append(slugs, s)
		}
	}
	for _, s := range data.TopPlugins() {
		add(s)
	}
	top := len(slugs)
	if l, ok := ss.opts.Advisor.(PluginLister); ok {
		for _, s := range l.PluginSlugs(ctx) {
			add(s)
		}
	}
	// An advisor can know thousands of plugins. With the default budget
	// probe as many as fit after the popular ones (two requests go to the
	// REST index and the baseline) instead of ending every deep scan
	// partial; an explicit --request-budget is honoured as given.
	var trimmed string
	if room := max(top, budget-2); ss.opts.RequestBudget <= 0 && len(slugs) > room {
		trimmed = fmt.Sprintf("plugin discovery probed %d of %d plugins with known advisories; raise --request-budget to probe the rest",
			room-top, len(slugs)-top)
		slugs = slugs[:room]
	}

	// The baseline: a readme for a plugin that cannot exist.
	if !spend() {
		return stopped(), true
	}
	missing := readmePath(ss.token)
	base, err := ss.get(ctx, "GET", missing)
	if err != nil {
		return "", false
	}
	if detectBlockPage(base) != nil {
		return "plugin discovery skipped readme probes because the site answered them with a block page", false
	}
	if base.Status == 200 && fingerprint.IsReadme(base.Body) {
		return "plugin discovery skipped readme probes: the site answers every readme.txt path with a readme", false
	}

	found := make([]*fingerprint.Component, len(slugs))
	next := make(chan int)
	var wg sync.WaitGroup
	for range ss.opts.Concurrency {
		wg.Go(func() {
			for i := range next {
				p := readmePath(slugs[i])
				r, err := ss.get(ctx, "GET", p)
				if err == nil && r.Status == 200 && detectBlockPage(r) == nil && fingerprint.IsReadme(r.Body) &&
					(base.Status != 200 || !similar(r, p, base, missing)) {
					c := fingerprint.Component{Type: "plugin", Slug: slugs[i], Source: "readme",
						FoundBy: fingerprint.FoundByReadme, Confidence: fingerprint.ConfidenceHigh}
					if m := stableTag.FindSubmatch(r.Body); m != nil {
						c.Version = string(m[1])
					} else {
						c.Source = ""
					}
					found[i] = &c
				}
				// Most probes miss; their bodies are not kept for the
				// rest of the scan.
				ss.forget("GET " + p)
			}
		})
	}
feed:
	for i := range slugs {
		if !spend() {
			budgetHit = true
			break
		}
		select {
		case next <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	for _, c := range found {
		if c != nil {
			fp.AddComponent(*c)
		}
	}
	if budgetHit {
		return stopped(), true
	}
	return trimmed, false
}

func readmePath(slug string) string { return "/wp-content/plugins/" + slug + "/readme.txt" }

// forget drops the body cached under key; the status and headers stay.
func (ss *session) forget(key string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if f := ss.cache[key]; f != nil && f.resp != nil {
		ss.drop(f)
	}
}
