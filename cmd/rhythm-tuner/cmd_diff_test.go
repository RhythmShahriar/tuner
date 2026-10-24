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
		{[]string{old, filepath.Join(t.TempDir(), "missing.json")}, exitError, "no such file"},
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
