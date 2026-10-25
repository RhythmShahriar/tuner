// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package watch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
)

// Digest sums up one run's report plus what changed since the run
// before it when there was one.
type Digest struct {
	Sites    int                     `json:"sites"`    // targets in the report
	Findings int                     `json:"findings"` // findings across them
	Counts   map[engine.Severity]int `json:"counts"`   // findings per severity
	// Compared is false on the first run, when New and Fixed mean nothing.
	Compared bool `json:"compared"`
	New      int  `json:"new"`   // findings that are new since the last run
	Fixed    int  `json:"fixed"` // findings gone since the last run
}

// String reads "3 sites, 12 findings (1 critical, 2 high, 9 low); 2 new,
// 1 fixed since the last run".
func (d Digest) String() string {
	var b strings.Builder
	b.WriteString(plural(d.Sites, "site"))
	b.WriteString(", ")
	b.WriteString(plural(d.Findings, "finding"))
	var parts []string
	for _, s := range engine.Severities {
		if n := d.Counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	if len(parts) > 0 {
		b.WriteString(" (" + strings.Join(parts, ", ") + ")")
	}
	if d.Compared {
		fmt.Fprintf(&b, "; %d new, %d fixed since the last run", d.New, d.Fixed)
	}
	return b.String()
}

// plural is "1 word" or "n words".
func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// siteReport is the part of a Tuner JSON report a digest reads.
type siteReport struct {
	Target   string           `json:"target"`   // as the report names it
	Findings []engine.Finding `json:"findings"` // what the scan found
}

// readReport reads a JSON report: one site's object or a batch's array.
func readReport(path string) ([]siteReport, error) {
	b, err := os.ReadFile(path) //nolint:gosec // a report this watch wrote
	if err != nil {
		return nil, err
	}
	b = bytes.TrimSpace(b)
	var sites []siteReport
	if len(b) > 0 && b[0] == '{' {
		var one siteReport
		err = json.Unmarshal(b, &one)
		sites = []siteReport{one}
	} else {
		err = json.Unmarshal(b, &sites)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: not a Tuner JSON report: %w", path, err)
	}
	return sites, nil
}

// findingKey names a finding across runs: the site, check, place and the
// advisories behind it, so a new CVE for an installed plugin counts as new.
func findingKey(target string, f engine.Finding) string {
	ids := make([]string, 0, len(f.Advisories))
	for _, a := range f.Advisories {
		ids = append(ids, a.ID)
	}
	slices.Sort(ids)
	return strings.Join([]string{target, f.ID, f.Path, f.URL, strings.Join(ids, ",")}, "\x00")
}

// keys counts the findings of the sites in only (all sites when only is
// nil) by key. Two findings can share a key, so each is counted: one of
// a pair going away is one fix.
func keys(sites []siteReport, only map[string]bool) map[string]int {
	m := map[string]int{}
	for _, s := range sites {
		if only != nil && !only[s.Target] {
			continue
		}
		for _, f := range s.Findings {
			m[findingKey(s.Target, f)]++
		}
	}
	return m
}

// digest sums up the report at path, compared with prev when prev isn't "".
// A previous report that can't be read only skips the comparison.
func digest(path, prev string) (Digest, error) {
	sites, err := readReport(path)
	if err != nil {
		return Digest{}, err
	}
	d := Digest{Sites: len(sites), Counts: map[engine.Severity]int{}}
	for _, s := range sites {
		for _, f := range s.Findings {
			d.Findings++
			d.Counts[f.Severity]++
		}
	}
	if prev == "" {
		return d, nil
	}
	old, err := readReport(prev)
	if err != nil {
		return d, nil //nolint:nilerr // the comparison is a bonus
	}
	// A site missing from this run (it couldn't be reached, or left the
	// list) has fixed nothing.
	scanned := map[string]bool{}
	for _, s := range sites {
		scanned[s.Target] = true
	}
	now, before := keys(sites, nil), keys(old, scanned)
	d.Compared = true
	for k, n := range now {
		d.New += max(n-before[k], 0)
	}
	for k, n := range before {
		d.Fixed += max(n-now[k], 0)
	}
	return d, nil
}
