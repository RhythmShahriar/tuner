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
