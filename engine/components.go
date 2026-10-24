// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"regexp"
	"sync"

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
	}
	return "", "", ""
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
