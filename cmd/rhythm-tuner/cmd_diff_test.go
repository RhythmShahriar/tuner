// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/report"
)

func finding(id, path string, sev engine.Severity) engine.Finding {
	return engine.Finding{ID: id, Title: id, Severity: sev, Confidence: "high", Target: "https://a.test",
		URL: "https://a.test" + path, Path: path}
}

// saveReport writes findings as a JSON report the way scan --json does.
func saveReport(t *testing.T, name string, fs ...engine.Finding) string {
	t.Helper()
	var b bytes.Buffer
	r := report.New(&engine.Result{Target: "https://a.test", Findings: fs}, "test")
	if err := report.Write("json", &b, []report.Report{r}, report.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// lastWeek and thisWeek: the .env leak was fixed, a .git leak is new.
func diffFixtures(t *testing.T) (old, cur string) {
	old = saveReport(t, "last-week.json", finding("leak-dotenv", "/.env", engine.Critical), finding("xmlrpc", "/xmlrpc.php", engine.Low))
	cur = saveReport(t, "this-week.json", finding("xmlrpc", "/xmlrpc.php", engine.Low), finding("leak-git-config", "/.git/config", engine.High))
	return old, cur
}

func TestCmdDiffText(t *testing.T) {
	old, cur := diffFixtures(t)
	var out, errs bytes.Buffer
	if code := cmdDiff([]string{old, cur}, &out, &errs); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	want := "1 new, 1 fixed, 1 unchanged since " + old + "\n\nNew:\n[HIGH] leak-git-config - https://a.test/.git/config\n\nFixed:\n[CRITICAL] leak-dotenv - https://a.test/.env\n"
	if out.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestCmdDiffJSON(t *testing.T) {
	old, cur := diffFixtures(t)
	var out, errs bytes.Buffer
	if code := cmdDiff([]string{"--json", old, cur}, &out, &errs); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	var got struct {
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v:\n%s", err, out.String())
	}
	if got.Counts["new"] != 1 || got.Counts["fixed"] != 1 || got.Counts["unchanged"] != 1 {
		t.Errorf("counts = %v", got.Counts)
	}
}

func TestCmdDiffMarkdown(t *testing.T) {
	old, cur := diffFixtures(t)
	var out, errs bytes.Buffer
	if code := cmdDiff([]string{old, cur, "--md"}, &out, &errs); code != exitOK || !strings.Contains(out.String(), "## New\n") {
		t.Errorf("exit %d:\n%s%s", code, out.String(), errs.String())
	}
}

func TestCmdDiffExitCodes(t *testing.T) {
	old, cur := diffFixtures(t)
	notReport := filepath.Join(t.TempDir(), "other.json")
	if err := os.WriteFile(notReport, []byte(`{"name": "x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		want int
		msg  string
	}{
		{[]string{old, cur, "--fail-on-new", "high"}, exitFindings, ""},
		{[]string{old, cur, "--fail-on-new", "critical"}, exitOK, ""}, // the new one is high
		{[]string{cur, cur, "--fail-on-new", "info"}, exitOK, ""},     // nothing new
		{[]string{old}, exitUsage, "diff takes two JSON reports"},
		{[]string{old, cur, "--json", "--md"}, exitUsage, "pick one of --json and --md"},
		{[]string{old, cur, "--fail-on-new", "severe"}, exitUsage, `--fail-on-new "severe": want one of`},
		{[]string{old, filepath.Join(t.TempDir(), "missing.json")}, exitError, "missing.json"}, // not the OS's wording, which differs on Windows
		{[]string{old, notReport}, exitError, "not a Tuner JSON report"},
	} {
		var out, errs bytes.Buffer
		if code := cmdDiff(c.args, &out, &errs); code != c.want || !strings.Contains(errs.String(), c.msg) {
			t.Errorf("%v: exit %d, want %d; stderr %q", c.args, code, c.want, errs.String())
		}
	}
	var out bytes.Buffer
	if code := cmdDiff([]string{"--help"}, &out, &out); code != exitOK || !strings.Contains(out.String(), "rhythm tuner diff <old.json> <new.json>") {
		t.Errorf("--help: exit %d:\n%s", code, out.String())
	}
}

// The reviewer's repro: before.json scanned one site and failed another.
// A scan of the failed site compared with it has everything new.
func TestSinceWithFailedTargetInBefore(t *testing.T) {
	leaky, clean := leakySite(t), cleanSite(t)
	before := filepath.Join(t.TempDir(), "before.json")
	// clean is scanned; the leaky site is listed as failed.
	code, out, errs := tuner(t, "scan", clean.URL, "--json-array", "--no-vulns")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var batch []json.RawMessage
	if err := json.Unmarshal([]byte(out), &batch); err != nil {
		t.Fatal(err)
	}
	failed, _ := json.Marshal(map[string]string{"target": leaky.URL, "error": "can't reach"})
	data, _ := json.Marshal(append(batch, failed))
	os.WriteFile(before, data, 0o600)

	code, _, errs = tuner(t, "scan", leaky.URL, "--since", before, "--fail-on-new", "critical", "-q", "--no-vulns")
	if code != exitFindings || !strings.Contains(errs, "fixed since") || strings.Contains(errs, "0 new,") {
		t.Errorf("--since: exit %d, stderr %q", code, errs)
	}

	after := filepath.Join(t.TempDir(), "after.json")
	if code, _, errs := tuner(t, "scan", leaky.URL, "-o", after, "-q", "--no-vulns"); code != exitOK {
		t.Fatalf("after: exit %d: %s", code, errs)
	}
	var stdout, stderr bytes.Buffer
	code = cmdDiff([]string{before, after, "--fail-on-new", "critical"}, &stdout, &stderr)
	if code != exitFindings || strings.HasPrefix(stdout.String(), "0 new") {
		t.Errorf("diff: exit %d\n%s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "Not in the new scan, so not compared: "+clean.URL) {
		t.Errorf("diff lacks the not compared site:\n%s", stdout.String())
	}
}

// A narrowed scan does not report the checks it skipped as fixed.
func TestDiffSkippedChecksNotFixed(t *testing.T) {
	srv := leakySite(t)
	dir := t.TempDir()
	full, leaks := filepath.Join(dir, "a.json"), filepath.Join(dir, "lk.json")
	if code, _, errs := tuner(t, "scan", srv.URL, "-o", full, "-q", "--no-vulns"); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if code, _, errs := tuner(t, "scan", srv.URL, "--id", "leak-*", "-o", leaks, "-q", "--no-vulns"); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var out bytes.Buffer
	cmdDiff([]string{full, leaks}, &out, &bytes.Buffer{})
	if !strings.HasPrefix(out.String(), "0 new, 0 fixed, 1 unchanged since "+full+"; ") || !strings.Contains(out.String(), "not seen (not checked this time)") {
		t.Errorf("diff:\n%s", out.String())
	}
}
