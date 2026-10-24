// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Short names for Vuln.Sources.
const (
	SourceWPVulnerability = "WPVulnerability"
	SourceWordfence       = "Wordfence Intelligence"
)

// merge combines WPVulnerability's record with Wordfence's advisories for
// the same component. An advisory both list is kept once: they are the
// same when they share a CVE or, without one, have the same title and
// affected range. The merged advisory keeps WPVulnerability's range,
// gains the other's CVEs and references, takes the higher CVSS score and
// credits both sources. rec is not changed: it may be a cached copy.
func merge(rec *Record, wf []Vuln) *Record {
	out := *rec
	out.Vulns = make([]Vuln, len(rec.Vulns), len(rec.Vulns)+len(wf))
	for i, v := range rec.Vulns {
		v.Sources = []string{SourceWPVulnerability}
		out.Vulns[i] = v
	}
	for _, w := range wf {
		if i := slices.IndexFunc(out.Vulns, func(v Vuln) bool { return sameAdvisory(v, w) }); i >= 0 {
			out.Vulns[i] = combine(out.Vulns[i], w)
		} else {
			out.Vulns = append(out.Vulns, w)
		}
	}
	return &out
}

// sameAdvisory reports whether a and b describe the same flaw.
func sameAdvisory(a, b Vuln) bool {
	for _, c := range a.CVEs {
		if slices.Contains(b.CVEs, c) {
			return true
		}
	}
	if len(a.CVEs) > 0 && len(b.CVEs) > 0 {
		return false // both have CVEs, and they differ
	}
	return normTitle(a.Title) == normTitle(b.Title) && a.Min == b.Min && a.Max == b.Max
}

// normTitle compares titles loosely: case, punctuation and spacing aside.
func normTitle(s string) string {
	keep := func(r rune) bool { return 'a' <= r && r <= 'z' || '0' <= r && r <= '9' || r == '.' }
	return strings.Join(strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !keep(r) }), " ")
}

// combine folds b into a, which keeps its ID, title and range.
func combine(a, b Vuln) Vuln {
	a.CVEs = union(a.CVEs, b.CVEs)
	a.References = union(a.References, b.References)
	if len(a.References) > 6 {
		a.References = a.References[:6]
	}
	a.Sources = union(a.Sources, b.Sources)
	if b.CVSS > a.CVSS {
		a.CVSS, a.Vector = b.CVSS, b.Vector
		if b.Severity != "" {
			a.Severity = b.Severity
		}
	}
	if a.Severity == "" {
		a.Severity = b.Severity
	}
	a.KEV = a.KEV || b.KEV
	if a.Description == "" {
		a.Description = b.Description
	}
	if a.Published == "" || b.Published != "" && b.Published < a.Published {
		a.Published = b.Published
	}
	return a
}

// union appends b's items missing from a, keeping a's order.
func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// source credits the data behind advisories: WPVulnerability, and
// Wordfence Intelligence when it contributed one.
func (a *Advisor) source(vs []Vuln) string {
	w := a.Client.Wordfence
	if w != nil && slices.ContainsFunc(vs, func(v Vuln) bool { return slices.Contains(v.Sources, SourceWordfence) }) {
		return Source + "; " + w.Source()
	}
	return Source
}

// wordfenceWarning explains a feed that couldn't be loaded. The error
// never holds the API key.
func wordfenceWarning(err error) string {
	if errors.Is(err, ErrOffline) || errors.Is(err, ErrOldCache) {
		return "Wordfence Intelligence feed not cached; run once online to cache it"
	}
	return fmt.Sprintf("couldn't fetch the Wordfence Intelligence feed (%v); matched with WPVulnerability alone", err)
}
