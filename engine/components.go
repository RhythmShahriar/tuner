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
