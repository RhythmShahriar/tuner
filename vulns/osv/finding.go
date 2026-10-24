// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package osv

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/vulns"
)

// FindingPrefix starts the ID of every Composer package finding; the rest
// is the package name with "/" as "-", e.g. vuln-composer-guzzlehttp-guzzle.
const FindingPrefix = "vuln-composer-"

// FindingID is the ID of the finding about package name.
func FindingID(name string) string { return FindingPrefix + strings.ReplaceAll(name, "/", "-") }

// Finding builds the one finding that lists every advisory affecting p,
// like the WordPress advisor's vuln-plugin-* findings. The caller says
// where p was found by setting URL and Path.
func Finding(p Package, vs []Vuln) engine.Finding {
	worst := engine.Info
	fixedIn := ""
	unfixed := 0
	var advisories []engine.Advisory
	for _, v := range vs {
		sev := severity(v.DatabaseSpecific.Severity)
		if r := cmp.Or(sev, engine.Medium); r.Rank() < worst.Rank() {
			worst = r
		}
		fx := v.FixedIn(p)
		if fx == "" {
			unfixed++
		} else if fixedIn == "" || vulns.Compare(fx, fixedIn) > 0 {
			fixedIn = fx
		}
		ad := engine.Advisory{ID: v.ID, Title: cmp.Or(strings.TrimSpace(v.Summary), v.ID), Severity: sev, FixedIn: fx}
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				ad.CVEs = append(ad.CVEs, a)
			}
		}
		for _, r := range v.References {
			if r.Type == "ADVISORY" || r.Type == "WEB" {
				ad.References = append(ad.References, r.URL)
			}
		}
		ad.References = append(ad.References, "https://osv.dev/vulnerability/"+v.ID)
		advisories = append(advisories, ad)
	}
	slices.SortStableFunc(advisories, func(x, y engine.Advisory) int {
		return cmp.Compare(rankOr(x.Severity), rankOr(y.Severity))
	})

	var ev []string
	for _, ad := range advisories[:min(len(advisories), 5)] {
		line := strings.ToUpper(string(cmp.Or(ad.Severity, "unrated")))
		if len(ad.CVEs) > 0 {
			line += " " + ad.CVEs[0]
		}
		line += " " + ad.Title
		if ad.FixedIn != "" {
			line += " (fixed in " + ad.FixedIn + ")"
		}
		ev = append(ev, line)
	}
	if n := len(advisories) - 5; n > 0 {
		ev = append(ev, fmt.Sprintf("…and %d more", n))
	}

	plural := "ies"
	if len(vs) == 1 {
		plural = "y"
	}
	fix := fmt.Sprintf("Update %s to %s or later: composer update %s --with-dependencies", p.Name, fixedIn, p.Name)
	switch {
	case fixedIn == "":
		fix = fmt.Sprintf("No fixed version is known. Remove or replace %s.", p.Name)
	case unfixed > 0:
		fix += fmt.Sprintf(". %d of the issues have no known fixed version.", unfixed)
	}
	tags := []string{"vuln", "composer"}
	if strings.HasPrefix(p.Name, "laravel/") {
		tags = append(tags, "laravel")
	}
	f := engine.Finding{
		ID:         FindingID(p.Name),
		Title:      fmt.Sprintf("%s %s: %d known vulnerabilit%s", p.Name, p.Version, len(vs), plural),
		Severity:   worst,
		Confidence: "high",
		Evidence:   engine.Evidence{Request: "version match", Matched: ev},
		Impact:     fmt.Sprintf("%d published vulnerabilities affect %s %s; the worst is rated %s.", len(vs), p.Name, p.Version, worst),
		Fix:        fix,
		Tags:       tags,
		Advisories: advisories,
		Source:     Source,
	}
	if len(advisories) > 0 {
		f.References = advisories[0].References
	}
	return f
}

// FixedIn returns the lowest fixed version above p's version, for p, or ""
// if none is known.
func (v Vuln) FixedIn(p Package) string {
	best := ""
	for _, a := range v.Affected {
		if !strings.EqualFold(a.Package.Name, p.Name) {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				fx := strings.TrimPrefix(e.Fixed, "v")
				if fx != "" && vulns.Compare(fx, p.Version) > 0 && (best == "" || vulns.Compare(fx, best) < 0) {
					best = fx
				}
			}
		}
	}
	return best
}

// severity maps GitHub's database_specific severity to Tuner's.
func severity(s string) engine.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return engine.Critical
	case "HIGH":
		return engine.High
	case "MODERATE", "MEDIUM":
		return engine.Medium
	case "LOW":
		return engine.Low
	}
	return ""
}

// rankOr ranks an unrated advisory as medium.
func rankOr(s engine.Severity) int {
	if r := s.Rank(); r >= 0 {
		return r
	}
	return engine.Medium.Rank()
}
