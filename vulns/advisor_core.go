// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

// coreAdvisor matches the WordPress core version: known vulnerabilities
// (vuln-core) and, without any, whether a newer release exists.
type coreAdvisor struct{}

// lookups looks up core only when the fingerprint read its version.
func (coreAdvisor) lookups(fp fingerprint.Result) []*lookup {
	if !fp.Has("wordpress") || fp.WordPress == "" {
		return nil
	}
	return []*lookup{{component: component{kind: "core", key: fp.WordPress, slug: "wordpress", version: fp.WordPress, path: "/"}}}
}

// fetch gets the advisories for the version and the latest release.
func (coreAdvisor) fetch(ctx context.Context, a *Advisor, l *lookup, _ time.Time) {
	a.fetchAdvisories(ctx, l)
	a.fetchLatest(ctx, l, "wordpress")
}

// advise reports known vulnerabilities, or else an outdated release:
// the vulnerability finding already says to update.
func (coreAdvisor) advise(base *url.URL, a *Advisor, ls []*lookup, _ time.Time) []engine.Finding {
	var out []engine.Finding
	for _, l := range ok(ls) {
		f, hasVulns := a.vulnFinding(base, l)
		if hasVulns {
			out = append(out, f)
		} else if l.rel != nil && l.rel.Latest != "" && Compare(l.version, l.rel.Latest) < 0 {
			out = append(out, finding(base, "wp-core-outdated", engine.Low, "/",
				fmt.Sprintf("WordPress %s is out of date", l.version),
				[]string{fmt.Sprintf("installed %s, latest %s", l.version, l.rel.Latest)},
				"Older releases miss security hardening and fixes.",
				fmt.Sprintf("Update WordPress to %s (Dashboard → Updates, or: wp core update).", l.rel.Latest),
				"wordpress", "outdated"))
		}
	}
	return out
}

// rules describes the core findings.
func (coreAdvisor) rules() []Rule {
	return []Rule{
		NewRule("vuln-core", false, engine.High, "WordPress core with known vulnerabilities", "vuln", "core", "wordpress"),
		NewRule("wp-core-outdated", false, engine.Low, "WordPress core out of date", "wordpress", "outdated"),
	}
}
