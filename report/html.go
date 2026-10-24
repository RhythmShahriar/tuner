// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
)

//go:embed html.tmpl
var htmlSource string

// htmlTemplate is parsed once. html/template escapes every value for
// where it lands (text, attribute, URL). Every value was cleaned by
// SafeText before that, so a site's Server header or a file name shows
// as text and never as markup.
var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper": func(s engine.Severity) string { return strings.ToUpper(string(s)) },
}).Parse(htmlSource))

// htmlPage is what the template renders.
type htmlPage struct {
	Title     string
	Brand     string
	Logo      template.URL // a data: URI built by LogoDataURI, never a remote URL
	Version   string
	SinceName string
	Overview  bool
	Sites     []htmlSite
	Failed    []TargetError
}

type htmlSite struct {
	Anchor      string
	Target      string
	Score       int
	ScoreClass  string
	Trend       string // "up 12 since last-week.json (was 60)"; "" without an earlier report
	TrendShort  string // "+12", for the overview
	TrendClass  string
	Notes       []string
	Fingerprint string
	Components  []htmlComponent
	Counts      []htmlCount
	Groups      []htmlGroup
	New         int
	Fixed       []htmlFixed
	Compared    bool // an earlier report was given for this site
	Baselined   int
	Checks      int
	Requests    int64
}

type htmlComponent struct{ Type, Slug, Version, Source string }

type htmlCount struct {
	Severity engine.Severity
	N        int
}

type htmlGroup struct {
	Severity engine.Severity
	Findings []htmlFinding
}

type htmlFinding struct {
	Title, ID, Confidence, Caveat, Place string
	Severity                             engine.Severity
	New                                  bool
	Was                                  engine.Severity
	Request                              string
	Status                               int
	Matched                              []string
	Secrets                              []string
	Impact, Fix, Source                  string
	Advisories                           []htmlAdvisory
	References                           []htmlLink
}

type htmlAdvisory struct {
	Severity, CVEs, FixedIn string
	Title                   htmlLink
	KEV                     bool
	New                     bool
}

// htmlLink is a link that renders only for http and https targets.
type htmlLink struct{ Text, Href string }

type htmlFixed struct {
	Severity engine.Severity
	Title    string
	Place    string
}

// writeHTML is the html writer: one self-contained page with inline CSS,
// no scripts and no remote assets, so it works offline and as an email
// attachment. A Content-Security-Policy in the page blocks scripts and
// remote loads even if something slipped through.
func writeHTML(w io.Writer, reports []Report, o WriteOptions) error {
	page := htmlPage{Brand: o.Brand.Name, Version: o.Version, SinceName: o.SinceName,
		Overview: len(reports)+len(o.Failed) > 1, Failed: o.Failed}
	if o.Brand.LogoPath != "" {
		logo, err := LogoDataURI(o.Brand.LogoPath)
		if err != nil {
			return err
		}
		page.Logo = template.URL(logo) //nolint:gosec // LogoDataURI only returns data: URIs it built
	}
	if page.Version == "" && len(reports) > 0 {
		page.Version = reports[0].Version
	}
	switch {
	case len(reports) == 1 && len(o.Failed) == 0:
		page.Title = "Security report: " + reports[0].Target
	default:
		page.Title = fmt.Sprintf("Security report: %d sites", len(reports)+len(o.Failed))
	}
	if page.Brand != "" {
		page.Title = page.Brand + " " + strings.ToLower(page.Title[:1]) + page.Title[1:]
	}
	for i, r := range reports {
		var old *Report
		if len(o.Since) > 0 {
			old = earlier(o.Since, len(reports), r)
		}
		page.Sites = append(page.Sites, htmlSiteFor(i, r, old, len(o.Since) > 0, o.SinceName))
	}
	return htmlTemplate.Execute(w, page)
}

func htmlSiteFor(i int, r Report, old *Report, compared bool, sinceName string) htmlSite {
	s := htmlSite{
		Anchor: fmt.Sprintf("site-%d", i+1), Target: r.Target, Score: r.Score, ScoreClass: scoreClass(r.Score),
		Notes: r.Status().Notes(), Fingerprint: r.Fingerprint.String(), Compared: compared,
		Baselined: r.Baselined, Checks: r.Checks, Requests: r.Requests,
	}
	for _, c := range r.Fingerprint.Components {
		s.Components = append(s.Components, htmlComponent{c.Type, c.Slug, or(c.Version, "unknown"), c.Source})
	}
	for _, sev := range engine.Severities {
		s.Counts = append(s.Counts, htmlCount{sev, r.Summary[sev]})
	}
	prev := previous(old)
	if old != nil {
		switch d := r.Score - old.Score; {
		case d > 0:
			s.Trend, s.TrendClass = fmt.Sprintf("up %d since %s (was %d)", d, sinceName, old.Score), "up"
		case d < 0:
			s.Trend, s.TrendClass = fmt.Sprintf("down %d since %s (was %d)", -d, sinceName, old.Score), "down"
		default:
			s.Trend, s.TrendClass = "unchanged since "+sinceName, "same"
		}
		s.TrendShort = fmt.Sprintf("%+d", r.Score-old.Score)
		if r.Score == old.Score {
			s.TrendShort = "±0"
		}
	}

	current := map[string]bool{}
	for _, sev := range engine.Severities {
		g := htmlGroup{Severity: sev}
		for _, f := range r.Findings {
			if f.Severity != sev {
				continue
			}
			fp := Fingerprint(f, "")
			current[fp] = true
			hf := htmlFindingFor(f)
			if compared {
				was, seen := prev[fp]
				hf.New = !seen || was.severity != f.Severity
				if seen && was.severity != f.Severity {
					hf.Was = was.severity
				}
				for i, a := range f.Advisories {
					if seen && !was.advisories[a.ID] {
						hf.Advisories[i].New = true
						hf.New = true
					}
				}
				if hf.New {
					s.New++
				}
			}
			g.Findings = append(g.Findings, hf)
		}
		if len(g.Findings) > 0 {
			s.Groups = append(s.Groups, g)
		}
	}
	if old != nil {
		for _, f := range old.Findings {
			if fp := Fingerprint(f, ""); !current[fp] {
				current[fp] = true
				s.Fixed = append(s.Fixed, htmlFixed{f.Severity, f.Title, Place(f)})
			}
		}
	}
	return s
}

func htmlFindingFor(f engine.Finding) htmlFinding {
	hf := htmlFinding{
		Title: f.Title, ID: f.ID, Severity: f.Severity, Confidence: f.Confidence, Place: Place(f),
		Request: f.Evidence.Request, Status: f.Evidence.Status, Matched: f.Evidence.Matched[:matchedLimit(f)],
		Impact: f.Impact, Fix: strings.TrimSpace(f.Fix), Source: f.Source,
	}
	if f.Confidence == "low" {
		hf.Caveat = strings.TrimPrefix(f.Caveat, "likely: ")
	}
	for _, sec := range f.Evidence.Secrets {
		hf.Secrets = append(hf.Secrets, sec.String())
	}
	for _, a := range f.Advisories {
		ha := htmlAdvisory{Severity: or(string(a.Severity), "unrated"), CVEs: or(strings.Join(a.CVEs, ", "), "none"),
			FixedIn: or(a.FixedIn, "no fix yet"), Title: htmlLink{Text: a.Title}, KEV: a.KEV}
		if len(a.References) > 0 {
			ha.Title.Href = safeHref(a.References[len(a.References)-1])
		}
		hf.Advisories = append(hf.Advisories, ha)
	}
	for _, ref := range f.References {
		hf.References = append(hf.References, htmlLink{Text: ref, Href: safeHref(ref)})
	}
	return hf
}

// safeHref returns target when it is an http or https URL (without user
// info) and "" otherwise, so a javascript: or data: reference from a site
// or an advisory feed renders as plain text.
func safeHref(target string) string {
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	u.User = nil
	return SafeText(u.String())
}

func scoreClass(score int) string {
	switch {
	case score >= 90:
		return "good"
	case score >= 70:
		return "fair"
	}
	return "poor"
}

type seenFinding struct {
	severity   engine.Severity
	advisories map[string]bool
}

// previous indexes an earlier report's findings by fingerprint, the way
// package diff matches them: a finding is new when its fingerprint is new,
// its severity changed or it has an advisory the earlier one didn't.
func previous(old *Report) map[string]seenFinding {
	m := map[string]seenFinding{}
	if old == nil {
		return m
	}
	for _, f := range old.Findings {
		fp := Fingerprint(f, "")
		s, ok := m[fp]
		if !ok {
			s = seenFinding{severity: f.Severity, advisories: map[string]bool{}}
		}
		for _, a := range f.Advisories {
			s.advisories[a.ID] = true
		}
		m[fp] = s
	}
	return m
}

// earlier finds r's report in since: the only one when each side has one
// report (so staging compares with production), else the one with the
// same target. It is nil for a site the earlier scan didn't have.
func earlier(since []Report, n int, r Report) *Report {
	if len(since) == 1 && n == 1 {
		return &since[0]
	}
	for i := range since {
		if sameTarget(since[i].Target, r.Target) {
			return &since[i]
		}
	}
	return nil
}

// sameTarget compares targets by TargetKey.
func sameTarget(a, b string) bool { return TargetKey(a) == TargetKey(b) }
