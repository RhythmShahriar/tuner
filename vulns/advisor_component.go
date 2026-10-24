// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

// A plugin or theme with no release for this long counts as abandoned.
const abandonedAfter = 2 * 365 * 24 * time.Hour

// componentAdvisor matches plugins and themes: known vulnerabilities
// (vuln-plugin-*, vuln-theme-*), closed on wordpress.org plus one summary
// each for those out of date, abandoned or with an unknown version.
type componentAdvisor struct{}

func (componentAdvisor) lookups(fp fingerprint.Result) []*lookup {
	var out []*lookup
	for _, c := range fp.Components {
		out = append(out, &lookup{component: component{kind: c.Type, key: c.Slug, slug: c.Slug, version: c.Version,
			path: "/wp-content/" + c.Type + "s/" + c.Slug + "/"}})
	}
	return out
}

func (componentAdvisor) fetch(ctx context.Context, a *Advisor, l *lookup, _ time.Time) {
	a.fetchAdvisories(ctx, l)
	a.fetchLatest(ctx, l, l.slug)
}

func (componentAdvisor) advise(base *url.URL, a *Advisor, ls []*lookup, now time.Time) []engine.Finding {
	var out []engine.Finding
	var outdated, abandoned, unverified []string
	for _, l := range ok(ls) {
		f, hasVulns := a.vulnFinding(base, l)
		if hasVulns {
			out = append(out, f)
		}
		if l.rec.Closed {
			out = append(out, closedFinding(base, l))
		}
		switch {
		case l.version == "" && len(l.rec.Vulns) > 0:
			unverified = append(unverified, fmt.Sprintf("%s (%d known in some versions)", l.slug, len(l.rec.Vulns)))
		case l.version != "" && !hasVulns && l.rel != nil && l.rel.Latest != "" && Compare(l.version, l.rel.Latest) < 0:
			outdated = append(outdated, fmt.Sprintf("%s %s → %s", l.slug, l.version, l.rel.Latest))
		}
		if l.rel != nil && !l.rel.LastUpdated.IsZero() && now.Sub(l.rel.LastUpdated) > abandonedAfter {
			abandoned = append(abandoned, fmt.Sprintf("%s (last release %s)", l.slug, l.rel.LastUpdated.Format("2006-01-02")))
		}
	}

	if len(outdated) > 0 {
		out = append(out, finding(base, "wp-components-outdated", engine.Low, "/wp-content/",
			fmt.Sprintf("%d plugins or themes out of date", len(outdated)), outdated,
			"Outdated plugins and themes are the most common way WordPress sites get compromised.",
			"Update them (Dashboard → Updates, or: wp plugin update --all && wp theme update --all).",
			"wordpress", "outdated"))
	}
	if len(abandoned) > 0 {
		out = append(out, finding(base, "wp-components-abandoned", engine.Low, "/wp-content/",
			fmt.Sprintf("%d plugins or themes look abandoned", len(abandoned)), abandoned,
			"No release in over two years. Future security issues are unlikely to be fixed.",
			"Replace them with maintained alternatives.", "wordpress", "abandoned"))
	}
	if len(unverified) > 0 {
		f := finding(base, "wp-components-unverified", engine.Info, "/wp-content/",
			fmt.Sprintf("Versions unknown for %d plugins or themes with known vulnerabilities", len(unverified)), unverified,
			"Tuner couldn't read their versions, so it can't tell whether the site is affected.",
			"Check the installed versions in the dashboard, or rerun with the default profile so readme.txt and style.css are read.",
			"wordpress", "vuln")
		f.Confidence = confidenceLow
		out = append(out, f)
	}
	return out
}

// closedFinding reports a plugin or theme wordpress.org closed.
func closedFinding(base *url.URL, l *lookup) engine.Finding {
	ev := []string{"closed on wordpress.org"}
	if l.rec.ClosedDate != "" {
		ev[0] += " on " + l.rec.ClosedDate
	}
	if l.rec.ClosedReason != "" {
		ev = append(ev, "reason: "+l.rec.ClosedReason)
	}
	f := finding(base, "wp-"+l.kind+"-closed", engine.Medium, l.path,
		fmt.Sprintf("%s %s was closed on wordpress.org", strings.ToUpper(l.kind[:1])+l.kind[1:], l.slug), ev,
		"Closed "+l.kind+"s get no updates, and are often closed because of an unfixed security issue.",
		"Remove it, or replace it with a maintained alternative.", "wordpress", "abandoned")
	f.Source = Source
	return f
}

func (componentAdvisor) rules() []Rule {
	return []Rule{
		NewRule("vuln-plugin-", true, engine.High, "Plugin with known vulnerabilities", "vuln", "plugin", "wordpress"),
		NewRule("vuln-theme-", true, engine.High, "Theme with known vulnerabilities", "vuln", "theme", "wordpress"),
		NewRule("wp-plugin-closed", false, engine.Medium, "Plugin closed on wordpress.org", "wordpress", "abandoned"),
		NewRule("wp-theme-closed", false, engine.Medium, "Theme closed on wordpress.org", "wordpress", "abandoned"),
		NewRule("wp-components-outdated", false, engine.Low, "Plugins or themes out of date", "wordpress", "outdated"),
		NewRule("wp-components-abandoned", false, engine.Low, "Plugins or themes that look abandoned", "wordpress", "abandoned"),
		NewRule("wp-components-unverified", false, engine.Info, "Plugins or themes with known vulnerabilities and an unknown version", "wordpress", "vuln"),
	}
}
