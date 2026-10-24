// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"slices"
	"testing"
)

func TestMerge(t *testing.T) {
	rec := &Record{Name: "P", Closed: true, Vulns: []Vuln{
		{ID: "w1", Title: "XSS", CVEs: []string{"CVE-1"}, CVSS: 6.1, Severity: "medium", References: []string{"https://a"}, Max: "2.0", MaxOp: "lt"},
		{ID: "w2", Title: "SQL Injection in search", Max: "1.5", MaxOp: "lt"},
		{ID: "w3", Title: "Other", CVEs: []string{"CVE-3"}},
	}}
	wf := []Vuln{
		{ID: "f1", Title: "P <= 1.9 - Cross-Site Scripting", CVEs: []string{"CVE-1"}, CVSS: 7.2, Severity: "high", Vector: "V", References: []string{"https://wf/f1", "https://a"}, Sources: []string{SourceWordfence}},
		{ID: "f2", Title: "SQL injection in Search!", Max: "1.5", MaxOp: "lt", Sources: []string{SourceWordfence}},
		{ID: "f3", Title: "Other", CVEs: []string{"CVE-4"}, Sources: []string{SourceWordfence}},
		{ID: "f4", Title: "New", Sources: []string{SourceWordfence}},
	}
	got := merge(rec, wf)
	if len(got.Vulns) != 5 || !got.Closed || got.Name != "P" {
		t.Fatalf("merged %+v", got)
	}
	// Same CVE: once, WPVulnerability's ID and range, the higher score, both credited.
	if v := got.Vulns[0]; v.ID != "w1" || v.Max != "2.0" || v.CVSS != 7.2 || v.Severity != "high" || v.Vector != "V" ||
		!slices.Equal(v.References, []string{"https://a", "https://wf/f1"}) || !slices.Equal(v.Sources, []string{SourceWPVulnerability, SourceWordfence}) {
		t.Errorf("by CVE: %+v", v)
	}
	// No CVE: the title and range decide.
	if v := got.Vulns[1]; v.ID != "w2" || len(v.Sources) != 2 {
		t.Errorf("by title: %+v", v)
	}
	// Different CVEs stay apart even with the same title.
	if v := got.Vulns[2]; v.ID != "w3" || !slices.Equal(v.Sources, []string{SourceWPVulnerability}) {
		t.Errorf("w3: %+v", v)
	}
	if got.Vulns[3].ID != "f3" || got.Vulns[4].ID != "f4" {
		t.Errorf("union: %+v", got.Vulns[3:])
	}
	// The cached record is untouched.
	if rec.Vulns[0].CVSS != 6.1 || rec.Vulns[0].Sources != nil || len(rec.Vulns) != 3 {
		t.Errorf("input changed: %+v", rec.Vulns)
	}
	// A lower score from the feed doesn't replace a higher one.
	if v := combine(Vuln{CVSS: 9.8, Severity: "critical"}, Vuln{CVSS: 5, Severity: "medium"}); v.CVSS != 9.8 || v.Severity != "critical" {
		t.Errorf("lower score won: %+v", v)
	}
}

// TestMergeKeepsEveryRange covers a feed record with two affected ranges
// for one CVE: no range may be folded away.
func TestMergeKeepsEveryRange(t *testing.T) {
	wf := []Vuln{
		{ID: "f1", CVEs: []string{"CVE-2024-1"}, Min: "1.0", MinOp: "ge", Max: "1.5", MaxOp: "lt", Sources: []string{SourceWordfence}},
		{ID: "f1", CVEs: []string{"CVE-2024-1"}, Min: "2.0", MinOp: "ge", Max: "2.3", MaxOp: "lt", Sources: []string{SourceWordfence}},
	}
	affected := func(r *Record, v string) bool {
		return slices.ContainsFunc(r.Vulns, func(x Vuln) bool { return x.Affects(v) })
	}
	for name, rec := range map[string]*Record{
		"feed only": {Vulns: []Vuln{}},
		"one range listed": {Vulns: []Vuln{
			{ID: "w1", CVEs: []string{"CVE-2024-1"}, Min: "1.0", MinOp: "ge", Max: "1.5", MaxOp: "lt"},
		}},
		"wider range listed": {Vulns: []Vuln{
			{ID: "w1", CVEs: []string{"CVE-2024-1"}, Max: "1.4", MaxOp: "le"},
		}},
	} {
		got := merge(rec, wf)
		for _, v := range []string{"1.0", "1.4.5", "2.0", "2.1", "2.2.9"} {
			if !affected(got, v) {
				t.Errorf("%s: %s not affected: %+v", name, v, got.Vulns)
			}
		}
		for _, v := range []string{"1.5", "1.9", "2.3"} {
			if affected(got, v) {
				t.Errorf("%s: %s affected: %+v", name, v, got.Vulns)
			}
		}
		if len(got.Vulns) != 2 {
			t.Errorf("%s: want 2 advisories, got %+v", name, got.Vulns)
		}
	}
}

// TestMergeNegative checks that a matching advisory is still kept once
// and that ranges which don't touch stay apart.
func TestMergeNegative(t *testing.T) {
	rec := &Record{Vulns: []Vuln{{ID: "w1", CVEs: []string{"CVE-1"}, Max: "2.0", MaxOp: "lt"}}}
	same := merge(rec, []Vuln{{ID: "f1", CVEs: []string{"CVE-1"}, Max: "1.9", MaxOp: "le", Sources: []string{SourceWordfence}}})
	if len(same.Vulns) != 1 || same.Vulns[0].Max != "2.0" || same.Vulns[0].FixedIn() != "2.0" {
		t.Errorf("same flaw: %+v", same.Vulns)
	}
	apart := merge(rec, []Vuln{{ID: "f1", CVEs: []string{"CVE-1"}, Min: "2.0", MinOp: "ge", Max: "3.0", MaxOp: "lt", Sources: []string{SourceWordfence}}})
	if len(apart.Vulns) != 2 || apart.Vulns[1].ID != "f1" {
		t.Errorf("separate range: %+v", apart.Vulns)
	}
	if overlaps(Vuln{Max: "2.0", MaxOp: "lt"}, Vuln{Min: "2.0", MinOp: "ge"}) || !overlaps(Vuln{Max: "2.0", MaxOp: "le"}, Vuln{Min: "2.0", MinOp: "ge"}) {
		t.Error("touching bounds")
	}
	if !overlaps(Vuln{Max: "1.2", MaxOp: "eq"}, Vuln{Min: "1.0", MinOp: "ge", Max: "1.5", MaxOp: "lt"}) || overlaps(Vuln{Max: "1.2", MaxOp: "eq"}, Vuln{Min: "1.3", MinOp: "ge"}) {
		t.Error("eq bound")
	}
}

// Merging keeps at most six references but never drops a Wordfence
// record link, which the feed's terms ask for.
func TestMergeKeepsWordfenceLinks(t *testing.T) {
	a := Vuln{References: []string{"https://r/1", "https://r/2", "https://r/3", "https://r/4", "https://r/5", "https://r/6"}}
	b1 := Vuln{References: []string{wordfenceRecordURL + "one", "https://r/7"}}
	b2 := Vuln{References: []string{wordfenceRecordURL + "two"}}
	got := combine(combine(a, b1), b2)
	want := []string{"https://r/1", "https://r/2", "https://r/3", "https://r/4", "https://r/5", "https://r/6", wordfenceRecordURL + "one", wordfenceRecordURL + "two"}
	if !slices.Equal(got.References, want) {
		t.Errorf("references %v, want %v", got.References, want)
	}
}
