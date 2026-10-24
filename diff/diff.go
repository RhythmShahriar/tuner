// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package diff compares two scans: which findings are new, which were
// fixed and which are unchanged. It answers the question a weekly scan
// is for, what changed since last time.
package diff

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/report"
)

// Schema identifies the JSON layout WriteJSON writes.
const Schema = "rhythm-tuner-diff/v0"

// Entry is one finding in a comparison.
type Entry struct {
	Target      string         `json:"target"`
	Fingerprint string         `json:"fingerprint"`
	Finding     engine.Finding `json:"finding"`
	// Was is the finding's severity in the old scan, when it changed. A
	// finding whose severity changed counts as new.
	Was engine.Severity `json:"was,omitempty"`
	// NewAdvisories lists the advisories the old scan didn't have, for a
	// finding that was there before with fewer of them.
	NewAdvisories []engine.Advisory `json:"new_advisories,omitempty"`
}

// Result is what changed between two scans.
type Result struct {
	New       []Entry `json:"new"`
	Fixed     []Entry `json:"fixed"`
	Unchanged []Entry `json:"unchanged"`
	// NotScanned lists targets of the old scan the new one doesn't have
	// (or couldn't reach). Their findings are not counted as fixed.
	NotScanned []string `json:"not_scanned,omitempty"`
}

// Compare matches the findings of two scans. Findings match on their
// fingerprint, so a site that moved host or a local copy that moved folder
// still lines up; reports saved before fingerprints get theirs from the
// finding's ID and path, which is what a fingerprint is made of. A finding
// with advisories is compared one advisory at a time: the same plugin
// with a new advisory is new.
//
// One report on each side is compared whatever its target, so staging
// can be compared with production. With several, reports pair up by
// target.
func Compare(before, after []report.Report) Result {
	res := Result{New: []Entry{}, Fixed: []Entry{}, Unchanged: []Entry{}}
	if len(before) == 1 && len(after) == 1 {
		res.add(&before[0], &after[0])
		res.sort()
		return res
	}
	old := map[string]*report.Report{}
	for i := range before {
		old[report.TargetKey(before[i].Target)] = &before[i]
	}
	seen := map[string]bool{}
	for i := range after {
		k := report.TargetKey(after[i].Target)
		seen[k] = true
		res.add(old[k], &after[i])
	}
	for _, r := range before {
		if !seen[report.TargetKey(r.Target)] {
			res.NotScanned = append(res.NotScanned, r.Target)
		}
	}
	res.sort()
	return res
}

// add compares one target's reports; before is nil for a new target.
func (res *Result) add(before, after *report.Report) {
	type seen struct {
		f          engine.Finding
		advisories map[string]bool
	}
	old := map[string]*seen{}
	if before != nil {
		for _, f := range before.Findings {
			fp := report.Fingerprint(f, "")
			s := old[fp]
			if s == nil {
				s = &seen{f: f, advisories: map[string]bool{}}
				old[fp] = s
			}
			for _, a := range f.Advisories {
				s.advisories[a.ID] = true
			}
		}
	}
	current := map[string]bool{}
	for _, f := range after.Findings {
		fp := report.Fingerprint(f, "")
		current[fp] = true
		e := Entry{Target: after.Target, Fingerprint: fp, Finding: f}
		was := old[fp]
		switch {
		case was == nil:
			res.New = append(res.New, e)
			continue
		case was.f.Severity != f.Severity:
			e.Was = was.f.Severity
		}
		for _, a := range f.Advisories {
			if !was.advisories[a.ID] {
				e.NewAdvisories = append(e.NewAdvisories, a)
			}
		}
		if e.Was != "" || len(e.NewAdvisories) > 0 {
			res.New = append(res.New, e)
		} else {
			res.Unchanged = append(res.Unchanged, e)
		}
	}
	if before == nil {
		return
	}
	for _, f := range before.Findings {
		if fp := report.Fingerprint(f, ""); !current[fp] {
			current[fp] = true // a finding listed twice is fixed once
			res.Fixed = append(res.Fixed, Entry{Target: before.Target, Fingerprint: fp, Finding: f})
		}
	}
}

// sort puts the most severe first, keeping the scan's order otherwise.
func (res *Result) sort() {
	for _, es := range [][]Entry{res.New, res.Fixed, res.Unchanged} {
		slices.SortStableFunc(es, func(a, b Entry) int {
			return cmp.Compare(a.Finding.Severity.Rank(), b.Finding.Severity.Rank())
		})
	}
}

// NewAtOrAbove reports whether a new finding is at least as severe as level.
func (res Result) NewAtOrAbove(level engine.Severity) bool {
	return slices.ContainsFunc(res.New, func(e Entry) bool {
		r := e.Finding.Severity.Rank()
		return r >= 0 && r <= level.Rank()
	})
}

// Summary is one line for a log, e.g. "3 new, 1 fixed since last-week.json".
func (res Result) Summary(since string) string {
	return fmt.Sprintf("%d new, %d fixed since %s", len(res.New), len(res.Fixed), report.SafeText(since))
}

// Line renders an entry for a terminal or log:
// "[HIGH] gallery 1.5: 2 known vulnerabilities (1 new: CVE-2026-2) - /wp-content/plugins/gallery/".
func (e Entry) Line() string {
	f := e.Finding
	title := e.title()
	if e.Was != "" {
		title += " (was " + string(e.Was) + ")"
	}
	label := strings.ToUpper(string(f.Severity))
	if f.Confidence == "low" {
		label += ", likely"
	}
	return report.SafeText(fmt.Sprintf("[%s] %s - %s", label, title, report.Place(f)))
}

// title is the finding's title, naming the advisories that are new.
func (e Entry) title() string {
	n := len(e.NewAdvisories)
	if n == 0 {
		return e.Finding.Title
	}
	var ids []string
	for _, a := range e.NewAdvisories {
		ids = append(ids, cmp.Or(firstOf(a.CVEs), a.ID))
	}
	return e.Finding.Title + fmt.Sprintf(" (%d new: %s)", n, strings.Join(ids, ", "))
}

func firstOf(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

// WriteText writes the comparison for a terminal or log. since names the
// old scan, e.g. its file name.
func WriteText(w io.Writer, res Result, since string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%d new, %d fixed, %d unchanged since %s\n", len(res.New), len(res.Fixed), len(res.Unchanged), report.SafeText(since))
	for _, part := range []struct {
		title   string
		entries []Entry
	}{{"New", res.New}, {"Fixed", res.Fixed}} {
		if len(part.entries) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n%s:\n", part.title)
		for _, e := range part.entries {
			b.WriteString(e.Line() + "\n")
		}
	}
	if len(res.NotScanned) > 0 {
		fmt.Fprintf(&b, "\nNot in the new scan, so not compared: %s\n", report.SafeText(strings.Join(res.NotScanned, ", ")))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// WriteMarkdown writes the comparison for an issue or pull request.
func WriteMarkdown(w io.Writer, res Result, since string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Tuner changes since %s\n\n", report.MDText(since))
	fmt.Fprintf(&b, "**%d new** · **%d fixed** · %d unchanged\n", len(res.New), len(res.Fixed), len(res.Unchanged))
	for _, part := range []struct {
		title   string
		entries []Entry
	}{{"New", res.New}, {"Fixed", res.Fixed}} {
		if len(part.entries) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n## %s\n\n| Severity | Finding | Path | Target |\n|---|---|---|---|\n", part.title)
		for _, e := range part.entries {
			f := e.Finding
			sev := strings.ToUpper(string(f.Severity))
			if e.Was != "" {
				sev += " (was " + strings.ToUpper(string(e.Was)) + ")"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", report.MDText(sev), report.MDText(e.title()), report.MDCode(f.Path), report.MDText(e.Target))
		}
	}
	if len(res.NotScanned) > 0 {
		var ts []string
		for _, t := range res.NotScanned {
			ts = append(ts, report.MDText(t))
		}
		fmt.Fprintf(&b, "\nNot in the new scan, so not compared: %s\n", strings.Join(ts, ", "))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// WriteJSON writes the comparison as JSON for scripts.
func WriteJSON(w io.Writer, res Result, since string) error {
	out := struct {
		Schema string         `json:"schema"`
		Since  string         `json:"since"`
		Counts map[string]int `json:"counts"`
		Result
	}{Schema, report.SafeText(since), map[string]int{"new": len(res.New), "fixed": len(res.Fixed), "unchanged": len(res.Unchanged)}, res}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
