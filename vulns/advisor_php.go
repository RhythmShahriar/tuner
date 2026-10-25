// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"context"
	"net/url"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

// phpAdvisor matches the PHP version: known vulnerabilities (vuln-php),
// including those inferred for an end-of-life branch, plus the end of life
// itself (php-eol). When the site runs PHP but hides the version, it
// lists the recent flaws that can't be ruled out (php-version-hidden).
type phpAdvisor struct{}

// lookups looks up the PHP version the fingerprint read. A site that runs
// PHP but hides the version gets a php-hidden lookup instead.
func (phpAdvisor) lookups(fp fingerprint.Result) []*lookup {
	switch {
	case fp.PHP != "":
		return []*lookup{{component: component{kind: "php", key: fp.PHP, slug: "PHP", version: fp.PHP, path: "/", build: fp.PHPBuild, source: fp.PHPSource}}}
	case fp.Has("php"):
		return []*lookup{{component: component{kind: "php-hidden", slug: "PHP", path: "/"}}}
	}
	return nil
}

// fetch gets the advisories for the version, plus those found later on an
// end-of-life branch. For php-hidden it gets the recent critical flaws
// in supported branches.
func (phpAdvisor) fetch(ctx context.Context, a *Advisor, l *lookup, now time.Time) {
	if l.kind == "php-hidden" {
		var err error
		l.flaws, l.branches, l.stale, err = a.recentPHPFlaws(ctx, now)
		l.did("recent PHP advisories", err)
		return
	}
	if !a.fetchAdvisories(ctx, l) {
		return
	}
	newer, from, stale, err := a.newerPHPFlaws(ctx, l.rec, l.version, now)
	if newer != nil || from != "" || err != nil {
		l.did("newer PHP advisories", err) // only end-of-life branches ask
	}
	l.newer, l.newerFrom = newer, from
	l.stale = l.stale || stale
}

// advise reports known vulnerabilities and end-of-life branches. A hidden
// version is reported only when every lookup worked, since the finding
// claims recent flaws exist.
func (phpAdvisor) advise(base *url.URL, a *Advisor, ls []*lookup, now time.Time) []engine.Finding {
	var out []engine.Finding
	for _, l := range ls {
		if l.kind == "php-hidden" {
			if f, found := hiddenPHPFinding(base, l.flaws, l.branches); len(l.failures) == 0 && found {
				out = append(out, f)
			}
			continue
		}
		if l.err != nil {
			continue
		}
		if f, found := a.vulnFinding(base, l); found {
			out = append(out, f)
		}
		if f, found := a.eolFinding(base, l, now); found {
			out = append(out, f)
		}
	}
	return out
}

// rules describes the PHP findings.
func (phpAdvisor) rules() []Rule {
	return []Rule{
		NewRule("vuln-php", false, engine.High, "PHP version with known vulnerabilities", "vuln", "php"),
		NewRule("php-eol", false, engine.High, "PHP branch past end of life", "php", "outdated"),
		NewRule("php-version-hidden", false, engine.Medium, "PHP version hidden while recent critical flaws are out", "php", "vuln"),
	}
}
