// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
)

// Baseline holds findings that were accepted earlier and should no longer
// be reported. Any previous JSON report works as a baseline file.
//
// Findings match on their Fingerprint, so a baseline keeps working when
// the site moves host or a local copy moves folder. A finding that lists
// advisories is accepted one advisory at a time: when a plugin that was
// accepted with one low advisory gains a critical one, the finding comes
// back with only the new advisory.
//
// A baseline saved from one target matches any target, so staging's
// baseline works for production. A baseline saved from a batch holds each
// site's findings under that site: accepting a finding on one client's
// site must not hide it on another's.
type Baseline struct {
	keys map[string]bool // fingerprints; fingerprint + " " + advisory ID for advisories
	// scoped says keys start with the target's TargetKey and a space,
	// for a baseline saved from several targets.
	scoped bool
	// legacy holds the "ID URL" keys of reports saved before fingerprints.
	// They still count for one release, for findings without advisories.
	legacy map[string]bool
	old    string // the file, when it was saved before fingerprints
}

func advisoryKey(fp, id string) string { return fp + " " + id }

// scope is the prefix of target's keys: "" for a single-target baseline.
func (b Baseline) scope(target string) string {
	if !b.scoped {
		return ""
	}
	return TargetKey(target) + " "
}

func legacyKey(f engine.Finding) string { return f.ID + " " + f.URL }

// LoadBaseline reads a JSON report (one object or an array of them).
func LoadBaseline(path string) (Baseline, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from the user's --baseline flag
	if err != nil {
		return Baseline{}, err
	}
	// The same check as --since: a SARIF file, {} or [] would otherwise
	// load as a baseline that hides nothing.
	reports, failed, err := ReadJSON(bytes.NewReader(data))
	if err == nil && len(reports)+len(failed) == 0 {
		err = errors.New("not a Tuner JSON report: no reports in it")
	}
	if err != nil {
		return Baseline{}, err
	}
	type saved struct {
		Target   string
		Error    *string
		Findings []stampedFinding
	}
	var many []saved
	if err := json.Unmarshal(data, &many); err != nil {
		var one saved
		if err := json.Unmarshal(data, &one); err != nil {
			return Baseline{}, fmt.Errorf("not a Tuner JSON report: %w", err)
		}
		many = append(many, one)
	}
	// A batch also lists the targets it could not reach. They have no
	// findings but still make the baseline a batch one: a batch saved
	// while only client-a was up must not hide client-a's findings on
	// client-b next time. Only one object or a one-element array is
	// host-agnostic.
	scoped := len(many) > 1
	many = slices.DeleteFunc(many, func(r saved) bool { return r.Error != nil })
	b := Baseline{keys: map[string]bool{}, legacy: map[string]bool{}, scoped: scoped}
	for _, r := range many {
		scope := b.scope(r.Target)
		for _, f := range r.Findings {
			fp := f.Fingerprint
			if !strings.HasPrefix(fp, fingerprintPrefix) {
				b.old = path
				fp = Fingerprint(f.Finding, r.Target)
				if len(f.Advisories) == 0 {
					b.legacy[legacyKey(f.Finding)] = true
				}
			}
			fp = scope + fp
			if len(f.Advisories) == 0 {
				b.keys[fp] = true
			}
			for _, a := range f.Advisories {
				b.keys[advisoryKey(fp, a.ID)] = true
			}
		}
	}
	return b, nil
}

// Has reports whether f is in the baseline: for a finding with advisories,
// whether every one of them is. A batch baseline looks under f.Target.
// A zero Baseline has nothing.
func (b Baseline) Has(f engine.Finding) bool { return b.has(f.Target, f) }

// has is Has for a finding of the scan of target.
func (b Baseline) has(target string, f engine.Finding) bool {
	fp := b.scope(target) + Fingerprint(f, "")
	if len(f.Advisories) > 0 {
		return !slices.ContainsFunc(f.Advisories, func(a engine.Advisory) bool { return !b.keys[advisoryKey(fp, a.ID)] })
	}
	return b.keys[fp] || b.legacy[legacyKey(f)]
}

// Filter removes baselined findings from res and recomputes its score.
// A finding with some new advisories stays, narrowed to the new ones. It
// returns how many findings were hidden; the caller puts that in
// Report.Baselined. A batch baseline hides only findings of the target
// res scanned.
func (b Baseline) Filter(res *engine.Result) int {
	if len(b.keys) == 0 && len(b.legacy) == 0 {
		return 0
	}
	kept := res.Findings[:0]
	for _, f := range res.Findings {
		if b.has(res.Target, f) {
			continue
		}
		if len(f.Advisories) > 0 {
			fp := b.scope(res.Target) + Fingerprint(f, "")
			var fresh []engine.Advisory
			for _, a := range f.Advisories {
				if !b.keys[advisoryKey(fp, a.ID)] {
					fresh = append(fresh, a)
				}
			}
			f = narrow(f, fresh)
		}
		kept = append(kept, f)
	}
	n := len(res.Findings) - len(kept)
	res.Findings = kept
	res.Score = engine.Score(kept)
	if b.old != "" {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"baseline %s predates finding fingerprints; save a fresh one by running the scan without --baseline and with --json -o %s", b.old, b.old))
	}
	return n
}

var knownVulns = regexp.MustCompile(`: \d+ known vulnerabilit(?:y|ies)$`)

// narrow rewrites an advisory finding to list only fresh, the advisories
// the baseline doesn't accept. Title, evidence, severity and tags follow;
// the severity never rises above what the full finding had.
func narrow(f engine.Finding, fresh []engine.Advisory) engine.Finding {
	if len(fresh) == len(f.Advisories) {
		return f
	}
	accepted := len(f.Advisories) - len(fresh)

	// The advisors write one evidence line per advisory, in order, for the
	// first few; reuse those lines and build the rest the same way.
	lines := map[string]string{}
	for i, a := range f.Advisories {
		if i < len(f.Evidence.Matched) && !strings.HasPrefix(f.Evidence.Matched[i], "…and ") {
			lines[a.ID] = f.Evidence.Matched[i]
		}
	}
	const shown = 5
	var ev []string
	worst, kev := engine.Info, false
	for i, a := range fresh {
		if s := ratedOrMedium(a.Severity); s.Rank() < worst.Rank() {
			worst = s
		}
		kev = kev || a.KEV
		if i < shown {
			ev = append(ev, cmp.Or(lines[a.ID], advisoryLine(a)))
		}
	}
	if more := len(fresh) - shown; more > 0 {
		ev = append(ev, fmt.Sprintf("…and %d more", more))
	}
	if f.Severity.Rank() >= 0 && worst.Rank() < f.Severity.Rank() {
		worst = f.Severity
	}

	plural := "ies"
	if len(fresh) == 1 {
		plural = "y"
	}
	newTitle := fmt.Sprintf(": %d new known vulnerabilit%s", len(fresh), plural)
	if knownVulns.MatchString(f.Title) {
		f.Title = knownVulns.ReplaceAllLiteralString(f.Title, newTitle)
	} else {
		f.Title += fmt.Sprintf(" (%d new)", len(fresh))
	}

	f.Advisories = slices.Clone(fresh)
	f.Severity = worst
	f.Evidence.Matched = ev
	f.Tags = slices.DeleteFunc(slices.Clone(f.Tags), func(t string) bool { return t == "known-exploited" })
	if kev {
		f.Tags = append(f.Tags, "known-exploited")
	}
	if f.Impact != "" {
		f.Impact += fmt.Sprintf(" The baseline accepts %d of them, so only the new ones are listed.", accepted)
	}
	return f
}

// ratedOrMedium counts an unrated advisory as medium, as the advisors do.
func ratedOrMedium(s engine.Severity) engine.Severity {
	if s.Rank() < 0 {
		return engine.Medium
	}
	return s
}

// advisoryLine renders an advisory the way the advisors' evidence does,
// e.g. "CRITICAL CVE-2024-1234 SQL injection (fixed in 2.1) [actively exploited]".
func advisoryLine(a engine.Advisory) string {
	line := strings.ToUpper(string(cmp.Or(a.Severity, "unrated")))
	if len(a.CVEs) > 0 && a.Title != a.CVEs[0] {
		line += " " + a.CVEs[0]
	}
	line += " " + a.Title
	if a.FixedIn != "" {
		line += " (fixed in " + a.FixedIn + ")"
	}
	if a.KEV {
		line += " [actively exploited]"
	}
	return line
}
