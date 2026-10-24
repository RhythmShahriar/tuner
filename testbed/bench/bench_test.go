// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed

package main

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func testManifest(t *testing.T) *Manifest {
	t.Helper()
	m, err := LoadManifest(filepath.Join("..", "ground-truth.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestLoadManifest(t *testing.T) {
	m := testManifest(t)
	if len(m.Plugins) == 0 || len(m.Sites) == 0 {
		t.Fatal("manifest is empty")
	}
	if _, ok := m.Sites["main"]; !ok {
		t.Error("no main site")
	}
	if !m.Installed("akismet") || m.Installed("not-a-plugin") {
		t.Error("Installed is wrong")
	}
	// Vulnerable is a strict subset of installed.
	for _, s := range m.VulnerableSlugs() {
		if !m.Installed(s) {
			t.Errorf("%s is vulnerable but not installed", s)
		}
	}
}

func TestScorePlugins(t *testing.T) {
	m := &Manifest{Plugins: []Plugin{
		{Slug: "akismet", Version: "1", Vulnerable: false},
		{Slug: "elementor", Version: "1", Vulnerable: true},
		{Slug: "jetpack", Version: "1", Vulnerable: true},
	}}
	// Reported: one installed non-vulnerable, one installed vulnerable,
	// one false positive and a duplicate in a different case.
	found, missed, falsePos, vuln := scorePlugins(m, []string{"akismet", "Elementor", "ghost-plugin", "AKISMET"})
	if !slices.Equal(found, []string{"akismet", "elementor"}) {
		t.Errorf("found = %v", found)
	}
	if !slices.Equal(missed, []string{"jetpack"}) {
		t.Errorf("missed = %v", missed)
	}
	if !slices.Equal(falsePos, []string{"ghost-plugin"}) {
		t.Errorf("falsePos = %v", falsePos)
	}
	if !slices.Equal(vuln, []string{"elementor"}) {
		t.Errorf("vuln = %v", vuln)
	}
}

func TestScoreFiles(t *testing.T) {
	site := Site{Exposed: []Exposed{
		{Path: "/.env", Finding: "leak-dotenv", Severity: "critical"},
		{Path: "/backup.zip", Finding: "leak-archive-backup", Severity: "high"},
	}}
	found, missed := scoreFiles(site, []string{"/.ENV"})
	if !slices.Equal(found, []string{"/.env"}) {
		t.Errorf("found = %v (case-insensitive match expected)", found)
	}
	if !slices.Equal(missed, []string{"/backup.zip"}) {
		t.Errorf("missed = %v", missed)
	}
}

func TestScoreNotRunAndError(t *testing.T) {
	m := testManifest(t)
	site := m.Sites["main"]
	if s := score(m, "WPScan", "main", site, nil); !s.NotRun {
		t.Error("a nil report should be NotRun")
	}
	if s := score(m, "WPScan", "main", site, &Report{Err: "docker missing"}); s.Error == "" {
		t.Error("an errored report should carry the error")
	}
}

func TestParseTunerJSON(t *testing.T) {
	out := `rhythm tuner dev - scanning http://x
{"blocked_by":"","requests":42,"fingerprint":{"components":[
  {"type":"plugin","slug":"elementor"},
  {"type":"theme","slug":"twentytwentythree"},
  {"type":"plugin","slug":"akismet"}]},
 "findings":[{"id":"leak-dotenv","path":"/.env"},
  {"id":"wp-debug-log","path":"/wp-content/debug.log"},
  {"id":"header-csp","path":"/"}]}`
	doc, err := parseTunerJSON(out)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(doc.plugins, []string{"elementor", "akismet"}) {
		t.Errorf("plugins = %v (themes must be left out)", doc.plugins)
	}
	if !slices.Equal(doc.files, []string{"/.env", "/wp-content/debug.log"}) {
		t.Errorf("files = %v (non-leak findings must be left out)", doc.files)
	}
	if doc.requests != 42 || doc.blocked {
		t.Errorf("requests=%d blocked=%v", doc.requests, doc.blocked)
	}
}

func TestParseWPScanJSON(t *testing.T) {
	out := `{"plugins":{"elementor":{"version":{"number":"3.5.0"}},"akismet":{}}}`
	plugins, err := parseWPScanJSON(out)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(plugins)
	if !slices.Equal(plugins, []string{"akismet", "elementor"}) {
		t.Errorf("plugins = %v", plugins)
	}
}

func TestParseWpprobeJSON(t *testing.T) {
	out := `[{"url":"http://x","plugins":{"contact-form-7":{"version":"5.3.1"},"jetpack":{"version":"10.0"}}}]`
	plugins, err := parseWpprobeJSON(out)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(plugins)
	if !slices.Equal(plugins, []string{"contact-form-7", "jetpack"}) {
		t.Errorf("plugins = %v", plugins)
	}
}

func TestParseNucleiJSONL(t *testing.T) {
	out := strings.Join([]string{
		`{"template-id":"wordpress-detect","matched-at":"http://x/"}`,
		`{"template-id":"wordpress-plugin","matched-at":"http://x/wp-content/plugins/elementor/readme.txt"}`,
		`{"template-id":"wordpress-plugin","matched-at":"http://x/wp-content/plugins/akismet/"}`,
		"not json",
	}, "\n")
	plugins := parseNucleiJSONL(out)
	slices.Sort(plugins)
	if !slices.Equal(plugins, []string{"akismet", "elementor"}) {
		t.Errorf("plugins = %v", plugins)
	}
}

func TestPickTools(t *testing.T) {
	all, err := pickTools("")
	if err != nil || len(all) != len(allTools) {
		t.Fatalf("empty should mean all: %v %d", err, len(all))
	}
	some, err := pickTools("wpprobe")
	if err != nil {
		t.Fatal(err)
	}
	// Tuner is always included, even when not named.
	if len(some) != 2 || some[0].Key != "tuner" || some[1].Key != "wpprobe" {
		t.Errorf("pickTools(wpprobe) = %v", keys(some))
	}
	if _, err := pickTools("nope"); err == nil {
		t.Error("an unknown tool should error")
	}
}

func keys(ts []*Tool) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Key)
	}
	return out
}

func TestScoreboardRenders(t *testing.T) {
	m := testManifest(t)
	sites := siteOrder(m)
	if sites[0] != "main" {
		t.Fatalf("main should sort first, got %v", sites)
	}
	// A synthetic run: Tuner does well, WPScan misses the asset-only
	// plugins, wpprobe errors, Nuclei isn't run.
	var scores []Score
	main := m.Sites["main"]
	scores = append(scores, score(m, "Tuner", "main", main, &Report{
		Plugins: m.Slugs(), Files: []string{"/.env", "/wp-content/debug.log"},
		ScoresFiles: true, Requests: 120, Duration: 4 * time.Second,
	}))
	scores = append(scores, score(m, "WPScan", "main", main, &Report{
		Plugins: []string{"elementor", "akismet", "ghost"}, Requests: -1, Duration: 90 * time.Second,
	}))
	scores = append(scores, score(m, "wpprobe", "main", main, &Report{Err: "connection refused"}))
	scores = append(scores, Score{Tool: "Nuclei", Site: "main", NotRun: true})
	// The WAF site: Tuner blocks, WPScan is fooled.
	waf := m.Sites["waf"]
	scores = append(scores, score(m, "Tuner", "waf", waf, &Report{Blocked: true}))
	scores = append(scores, score(m, "WPScan", "waf", waf, &Report{Plugins: []string{}}))

	md := scoreboard(newBoard(m, sites, scores), "1.2.3", time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC))
	for _, want := range []string{
		"# Tuner benchmark", "rhythm-tuner 1.2.3", "## Plugins found on the main site",
		"| Tuner |", "not run", "error", "## Exposed files (Tuner)", "**found**",
		"**blocked** (correct)", "scanned a challenge page as the site",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("scoreboard is missing %q", want)
		}
	}
	// Ground truth leaks must never appear verbatim. The testbed holds no
	// real secrets; even so the scoreboard names files, not values.
	if strings.Contains(md, "ghost") && !strings.Contains(md, "False") {
		t.Error("false positives should be counted, not pasted")
	}
}
