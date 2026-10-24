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
// affected range. Their ranges must also overlap. The merged advisory keeps
// WPVulnerability's ID, widens its range to cover both, gains the other's
// CVEs and references, takes the higher CVSS score and credits both
// sources. rec is not changed: it may be a cached copy.
//
// The feed lists one advisory per affected range, all with the same ID
// and CVE. Each is matched against WPVulnerability's advisories only, never
// against another range of the same record. A range that doesn't
// overlap stays its own advisory: folding it in would hide the versions
// only the feed lists.
func merge(rec *Record, wf []Vuln) *Record {
	out := *rec
	n := len(rec.Vulns)
	out.Vulns = make([]Vuln, n, n+len(wf))
	for i, v := range rec.Vulns {
		v.Sources = []string{SourceWPVulnerability}
		out.Vulns[i] = v
	}
	for _, w := range wf {
		match := func(v Vuln) bool { return sameAdvisory(v, w) && overlaps(v, w) }
		if i := slices.IndexFunc(out.Vulns[:n], match); i >= 0 {
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
		return false // both have CVEs and they differ
	}
	return normTitle(a.Title) == normTitle(b.Title) && a.Min == b.Min && a.Max == b.Max
}

// normTitle compares titles loosely: case, punctuation and spacing aside.
func normTitle(s string) string {
	keep := func(r rune) bool { return 'a' <= r && r <= 'z' || '0' <= r && r <= '9' || r == '.' }
	return strings.Join(strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !keep(r) }), " ")
}

// bounds returns v's affected range as a lower and an upper bound, each
// "" when open. An "eq" bound pins both ends to one version.
func bounds(v Vuln) (lo, loOp, hi, hiOp string) {
	lo, loOp, hi, hiOp = v.Min, v.MinOp, v.Max, v.MaxOp
	if loOp == "eq" {
		hi, hiOp = lo, "le"
	}
	if hiOp == "eq" {
		if lo == "" {
			lo, loOp = hi, "ge"
		}
		hiOp = "le"
	}
	if loOp == "eq" {
		loOp = "ge"
	}
	return lo, loOp, hi, hiOp
}

// below reports whether some version is at or above lo and at or below hi.
func below(lo, loOp, hi, hiOp string) bool {
	if lo == "" || hi == "" {
		return true
	}
	c := Compare(lo, hi)
	return c < 0 || c == 0 && loOp != "gt" && hiOp != "lt"
}

// overlaps reports whether a and b share an affected version.
func overlaps(a, b Vuln) bool {
	alo, aloOp, ahi, ahiOp := bounds(a)
	blo, bloOp, bhi, bhiOp := bounds(b)
	return below(alo, aloOp, bhi, bhiOp) && below(blo, bloOp, ahi, ahiOp)
}

// widen sets a's range to the smallest one that holds both a and b, so a
// version either source calls affected stays affected.
func widen(a, b Vuln) Vuln {
	alo, aloOp, ahi, ahiOp := bounds(a)
	blo, bloOp, bhi, bhiOp := bounds(b)
	switch c := Compare(blo, alo); {
	case alo == "" || blo == "":
		alo, aloOp = "", ""
	case c < 0 || c == 0 && bloOp == "ge":
		alo, aloOp = blo, bloOp
	}
	switch c := Compare(bhi, ahi); {
	case ahi == "":
	case bhi == "":
		ahi, ahiOp, a.Unfixed = "", "", b.Unfixed
	case c > 0 || c == 0 && bhiOp == "le":
		ahi, ahiOp, a.Unfixed = bhi, bhiOp, b.Unfixed
	}
	a.Min, a.MinOp, a.Max, a.MaxOp = alo, aloOp, ahi, ahiOp
	return a
}

// bounded reports whether v lists an affected range at all. Core records
// and some feed entries don't: their range is unknown, not every version.
func bounded(v Vuln) bool { return v.Min != "" || v.Max != "" }

// combine folds b into a, which keeps its ID and title. When both list a
// range, a's widens to cover b's; an unknown range never replaces a known
// one.
func combine(a, b Vuln) Vuln {
	if bounded(a) && bounded(b) {
		a = widen(a, b)
	}
	a.CVEs = union(a.CVEs, b.CVEs)
	a.References = capReferences(union(a.References, b.References))
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

// maxReferences is how many references a merged advisory keeps, not
// counting Wordfence record links.
const maxReferences = 6

// capReferences keeps the first maxReferences references plus every
// Wordfence record link: Wordfence's terms ask for a link to each record
// whose data a finding uses, so attribution is never cut.
func capReferences(refs []string) []string {
	var out []string
	n := 0
	for _, r := range refs {
		switch {
		case strings.HasPrefix(r, wordfenceRecordURL):
			out = append(out, r)
		case n < maxReferences:
			out = append(out, r)
			n++
		}
	}
	return out
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
