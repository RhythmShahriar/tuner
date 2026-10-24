// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"cmp"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
)

// vulnFinding builds the one finding that lists every advisory affecting a
// component. It returns false if none apply.
func (a *Advisor) vulnFinding(base *url.URL, l *lookup) (engine.Finding, bool) {
	if l.version == "" || l.rec == nil {
		return engine.Finding{}, false
	}
	var affected []Vuln
	for _, v := range l.rec.Vulns {
		if v.Affects(l.version) {
			affected = append(affected, v)
		}
	}
	affected = append(affected, l.newer...)
	inferred := map[string]bool{}
	for _, v := range l.newer {
		inferred[v.ID] = true
	}
	if len(affected) == 0 {
		return engine.Finding{}, false
	}

	worst, kev, unfixed := engine.Info, 0, 0
	fixedIn := ""
	var advisories []engine.Advisory
	for _, v := range affected {
		sev := engine.Severity(v.Severity)
		if sev.Rank() < 0 {
			sev = "" // unrated
		}
		if r := cmp.Or(sev, engine.Medium); r.Rank() < worst.Rank() {
			worst = r
		}
		if v.KEV {
			kev++
		}
		if fx := v.FixedIn(); fx != "" && (fixedIn == "" || Compare(fx, fixedIn) > 0) {
			fixedIn = fx
		} else if fx == "" && l.kind != "core" {
			unfixed++
		}
		advisories = append(advisories, engine.Advisory{
			ID: v.ID, Title: v.Title, CVEs: v.CVEs, Severity: sev, CVSS: v.CVSS, KEV: v.KEV,
			FixedIn: v.FixedIn(), References: v.References,
		})
	}
	slices.SortStableFunc(advisories, func(x, y engine.Advisory) int {
		if x.KEV != y.KEV {
			if x.KEV {
				return -1
			}
			return 1
		}
		// Within a severity, flaws that will never be fixed on this branch first.
		return cmp.Or(cmp.Compare(rankOr(x.Severity), rankOr(y.Severity)), cmpBool(inferred[x.ID], inferred[y.ID]), cmp.Compare(y.CVSS, x.CVSS))
	})

	name := l.slug
	switch l.kind {
	case "core":
		name = "WordPress"
	case "theme":
		name = "theme " + l.slug
	}
	plural := "ies"
	if len(affected) == 1 {
		plural = "y"
	}
	title := fmt.Sprintf("%s %s: %d known vulnerabilit%s", name, l.version, len(affected), plural)

	var ev []string
	for _, ad := range advisories[:min(len(advisories), 5)] {
		line := strings.ToUpper(string(cmp.Or(ad.Severity, "unrated")))
		if len(ad.CVEs) > 0 && ad.Title != ad.CVEs[0] {
			line += " " + ad.CVEs[0]
		}
		line += " " + ad.Title
		if ad.FixedIn != "" {
			line += " (fixed in " + ad.FixedIn + ")"
		}
		if inferred[ad.ID] {
			line += " (no fix for this branch)"
		}
		if ad.KEV {
			line += " [actively exploited]"
		}
		ev = append(ev, line)
	}
	if n := len(advisories) - 5; n > 0 {
		ev = append(ev, fmt.Sprintf("…and %d more", n))
	}

	impact := fmt.Sprintf("%d published vulnerabilities affect %s %s; the worst is rated %s.", len(affected), name, l.version, worst)
	if kev > 0 {
		impact += fmt.Sprintf(" %d of them are in CISA's Known Exploited Vulnerabilities catalog: attackers use them in the wild.", kev)
	}
	if n := len(l.newer); n > 0 {
		impact += fmt.Sprintf(" %d were disclosed after PHP %s reached end of life: they're listed for PHP %s with no lower version bound, so they reach older branches too and will never be fixed on this one.",
			n, branchOf(l.version), l.newerFrom)
	}

	latest := ""
	if l.rel != nil {
		latest = l.rel.Latest
	}
	var fix string
	switch {
	case l.kind == "core":
		fix = "Update WordPress to the latest release"
		if latest != "" {
			fix += " (" + latest + ")"
		}
		fix += ": Dashboard → Updates, or: wp core update"
	case l.kind == "php" && len(l.newer) > 0:
		fix = fmt.Sprintf("Upgrade to a supported PHP branch (%s or later). PHP %s is end of life, so %d of these issues will never be fixed on it.",
			l.newerFrom, branchOf(l.version), len(l.newer))
	case fixedIn == "" && unfixed > 0:
		fix = fmt.Sprintf("No fixed version is known. Remove or replace %s.", name)
	case l.kind == "plugin" || l.kind == "theme":
		fix = fmt.Sprintf("Update %s to %s or later", name, fixedIn)
		if latest != "" && latest != fixedIn {
			fix += " (latest is " + latest + ")"
		}
		fix += fmt.Sprintf(": wp %s update %s", l.kind, l.slug)
		if unfixed > 0 {
			fix += fmt.Sprintf(". %d of the issues have no known fixed version; consider replacing it.", unfixed)
		}
	default:
		fix = fmt.Sprintf("Update %s", l.slug)
		if fixedIn != "" {
			fix += " to " + fixedIn + " or later"
		}
		fix += " from your OS or vendor packages."
	}

	tags := []string{"vuln", l.kind}
	if l.kind == "plugin" || l.kind == "theme" || l.kind == "core" {
		tags = append(tags, "wordpress")
	}
	if kev > 0 {
		tags = append(tags, "known-exploited")
	}
	f := finding(base, "vuln-"+l.kind+"-"+strings.ToLower(l.slug), worst, l.path, title, ev, impact, fix, tags...)
	if l.kind == "core" || l.kind == "php" || l.kind == "nginx" || l.kind == "apache" {
		f.ID = "vuln-" + l.kind
	}
	f.Advisories = advisories
	f.Source = a.source(affected)
	if len(advisories) > 0 {
		f.References = advisories[0].References
	}
	if l.source != "" {
		f.Evidence.Matched = append(f.Evidence.Matched, "version from "+l.source)
	}
	// Only inferred advisories: likely, not confirmed.
	if len(l.newer) == len(affected) {
		f.Confidence = confidenceLow
		f.Caveat = "inferred from a supported branch's advisories"
	}
	if l.kind != "plugin" && l.kind != "theme" && l.kind != "core" {
		a.distroCaveat(&f, l.build)
	}
	return f, true
}

// eolFinding reports a PHP or web server branch past its end of life,
// php-eol, nginx-eol or apache-eol. It returns false while the branch is
// supported or its end date is unknown.
func (a *Advisor) eolFinding(base *url.URL, l *lookup, now time.Time) (engine.Finding, bool) {
	eol, err := time.Parse("2006-01-02", l.rec.EndOfLife)
	if err != nil || !now.After(eol) {
		return engine.Finding{}, false
	}
	name := cmp.Or(l.rec.Name, l.slug+" "+l.version)
	sev, impact := engine.Medium, "No more security fixes are released for this branch."
	fix := fmt.Sprintf("Upgrade to a supported %s release.", l.slug)
	if l.kind == "php" {
		// PHP is what every request runs through. Its EOL
		// branches quietly collect new, never-fixed flaws.
		sev = engine.High
		impact = "No more security fixes are released for this branch: newly disclosed PHP flaws are never fixed on it. Vulnerability databases stop listing them for it."
		if n := len(l.newer); n > 0 {
			impact += fmt.Sprintf(" %d flaws disclosed since support ended likely affect it (see vuln-php).", n)
		}
		if l.newerFrom != "" {
			fix = fmt.Sprintf("Upgrade to a supported PHP branch (%s or later).", l.newerFrom)
		}
	}
	f := finding(base, l.kind+"-eol", sev, "/",
		fmt.Sprintf("%s is past end of life", name),
		[]string{fmt.Sprintf("%s %s, support ended %s", l.slug, l.version, l.rec.EndOfLife)},
		impact, fix, l.kind, "outdated")
	if l.source != "" {
		f.Evidence.Matched = append(f.Evidence.Matched, "version from "+l.source)
	}
	a.distroCaveat(&f, l.build)
	return f, true
}

// distroCaveat lowers confidence for versions reported by distro packages,
// which backport fixes without changing the upstream version number.
func (a *Advisor) distroCaveat(f *engine.Finding, build string) {
	if backported.MatchString(build) {
		f.Confidence = confidenceLow
		f.Caveat = "a distro build may already include the fix"
		f.Impact += " The server reports a distribution build (" + build + "), which may include backported fixes; check the package's security status before acting."
	}
}

// cmpBool orders true before false.
func cmpBool(x, y bool) int {
	switch {
	case x == y:
		return 0
	case x:
		return -1
	}
	return 1
}

func rankOr(s engine.Severity) int {
	if r := s.Rank(); r >= 0 {
		return r
	}
	return engine.Medium.Rank()
}

func finding(base *url.URL, id string, sev engine.Severity, path, title string, ev []string, impact, fix string, tags ...string) engine.Finding {
	u := *base
	u.Path = strings.TrimSuffix(base.Path, "/") + path
	return engine.Finding{
		ID:         id,
		Title:      title,
		Severity:   sev,
		Confidence: "high",
		URL:        u.String(),
		Path:       path,
		Evidence:   engine.Evidence{Request: "version match", Matched: ev},
		Impact:     impact,
		Fix:        fix,
		Tags:       tags,
	}
}
