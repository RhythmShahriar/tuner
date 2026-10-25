// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
)

// TestMain records every local finding the package's tests produce and
// fails the run when one isn't described by the Catalog: an ID missing,
// a tag it doesn't list or a severity above its own.
func TestMain(m *testing.M) {
	var mu sync.Mutex
	produced := map[string]engine.Finding{}
	var problems []string
	cat := map[string]RuleInfo{}
	for _, r := range Catalog() {
		cat[r.ID] = r
	}
	observe = func(opts Options, res *engine.Result) {
		mu.Lock()
		defer mu.Unlock()
		for _, f := range res.Findings {
			if !strings.HasPrefix(f.ID, "local-") {
				continue // advisor and OSV findings belong to the vulns catalog
			}
			r, ok := cat[f.ID]
			if !ok && opts.Rules != nil {
				continue // a test's own rule, standing in for a check pack's
			}
			produced[f.ID] = f
			switch {
			case !ok:
				problems = append(problems, f.ID+": not in the catalog")
			case f.Severity.Rank() < r.Severity.Rank():
				problems = append(problems, fmt.Sprintf("%s: severity %s above the catalog's %s", f.ID, f.Severity, r.Severity))
			}
			for _, t := range f.Tags {
				if ok && !slices.Contains(r.Tags, t) {
					problems = append(problems, fmt.Sprintf("%s: tag %q not in the catalog", f.ID, t))
				}
			}
		}
	}
	code := m.Run()
	if code == 0 && len(problems) > 0 {
		slices.Sort(problems)
		fmt.Fprintln(os.Stderr, "findings the catalog doesn't describe:\n  "+strings.Join(slices.Compact(problems), "\n  "))
		code = 1
	}
	// Only a full run sees every ID; -run narrows it.
	if code == 0 && len(produced) > 0 && !isNarrowed() {
		var unseen []string
		for id := range cat {
			if _, ok := produced[id]; !ok && (runtime.GOOS != "windows" || !unixOnly[id]) {
				unseen = append(unseen, id)
			}
		}
		if len(unseen) > 0 {
			slices.Sort(unseen)
			fmt.Fprintln(os.Stderr, "catalog IDs no test produces (add a fixture):\n  "+strings.Join(unseen, "\n  "))
			code = 1
		}
	}
	os.Exit(code)
}

// unixOnly are catalog IDs a scan can't produce on Windows, which has no
// Unix file modes.
var unixOnly = map[string]bool{"local-wp-config-perms": true}

// isNarrowed reports whether the test run was limited with -run or
// -skip, so not every test ran.
func isNarrowed() bool {
	for _, a := range os.Args[1:] {
		for _, f := range []string{"-test.run", "-test.skip", "-run", "-skip"} {
			if a == f || strings.HasPrefix(a, f+"=") {
				return true
			}
		}
	}
	return false
}

func TestCatalog(t *testing.T) {
	cat := Catalog()
	if !slices.IsSortedFunc(cat, func(a, b RuleInfo) int { return strings.Compare(a.ID, b.ID) }) {
		t.Error("catalog not sorted by ID")
	}
	ids := map[string]bool{}
	for _, r := range cat {
		switch {
		case ids[r.ID]:
			t.Errorf("%s listed twice", r.ID)
		case !strings.HasPrefix(r.ID, "local-"):
			t.Errorf("%s doesn't start with local-", r.ID)
		case r.Title == "" || strings.Contains(r.Title, "{"):
			t.Errorf("%s: title %q", r.ID, r.Title)
		case r.Severity.Rank() < 0:
			t.Errorf("%s: severity %q", r.ID, r.Severity)
		case r.HelpURI != HelpBase+r.ID:
			t.Errorf("%s: help %q", r.ID, r.HelpURI)
		case len(r.Tags) == 0 || r.Tags[0] != "local":
			t.Errorf("%s: tags %q", r.ID, r.Tags)
		}
		ids[r.ID] = true
	}
	// Every Go check and every built-in rule is there.
	for _, id := range append(slices.Clone(strayChecks), integrityChecks...) {
		if !ids[id] {
			t.Errorf("%s missing", id)
		}
	}
	for _, r := range BuiltinRules() {
		if !ids[r.ID] {
			t.Errorf("rule %s missing", r.ID)
		}
	}

	// local-db-admin is both Go (phpMyAdmin) and a rule (Adminer): once.
	byID := map[string]RuleInfo{}
	for _, r := range cat {
		byID[r.ID] = r
	}
	if r := byID["local-dotenv"]; r.Title != ".env file in the web root" || r.Severity != engine.High {
		t.Errorf("local-dotenv %+v", r) // high: extract.severity raises it when secrets are found
	}
	// Callers get copies.
	cat[0].Tags[0] = "changed"
	if Catalog()[0].Tags[0] != "local" {
		t.Error("Catalog shares its tag slices")
	}
}

func TestFileLabel(t *testing.T) {
	for globs, want := range map[string]string{"**/.env": ".env", "**/*.sql": "A", "": "A"} {
		var g []string
		if globs != "" {
			g = []string{globs}
		}
		if got := fileLabel(g); got != want {
			t.Errorf("fileLabel(%q) = %q, want %q", g, got, want)
		}
	}
}

// Every wp-config check counted in the summary is a catalog entry.
func TestWPConfigChecksInCatalog(t *testing.T) {
	cat := Catalog()
	for _, id := range wpConfigChecks {
		if !slices.ContainsFunc(cat, func(r RuleInfo) bool { return r.ID == id }) {
			t.Errorf("%s is not in the catalog", id)
		}
	}
	// The IDs wpConfig reports are the ones it counts.
	src, err := os.ReadFile("wordpress.go")
	if err != nil {
		t.Fatal(err)
	}
	_, body, _ := strings.Cut(string(src), "func (s *scan) wpConfig()")
	body, _, _ = strings.Cut(body, "\nfunc ")
	var reported []string
	for _, m := range regexp.MustCompile(`"(local-wp-[a-z-]+)"`).FindAllStringSubmatch(body, -1) {
		if !slices.Contains(reported, m[1]) {
			reported = append(reported, m[1])
		}
	}
	slices.Sort(reported)
	counted := slices.Sorted(slices.Values(wpConfigChecks))
	if !slices.Equal(reported, counted) {
		t.Errorf("wpConfig reports %v, counts %v", reported, counted)
	}
}
