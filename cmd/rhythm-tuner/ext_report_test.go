// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/report"
)

// planned parses scan flags into a fresh extension and runs its Plan.
func planned(t *testing.T, args ...string) (*reportExtension, error) {
	t.Helper()
	e := &reportExtension{}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	e.Flags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return e, e.Plan(&scanPlan{})
}

func thisWeek() []report.Report {
	return []report.Report{report.New(&engine.Result{Target: "https://a.test", Findings: []engine.Finding{
		finding("xmlrpc", "/xmlrpc.php", engine.Low), finding("leak-git-config", "/.git/config", engine.High),
	}}, "test")}
}

func TestReportExtensionSince(t *testing.T) {
	old, _ := diffFixtures(t)
	e, err := planned(t, "--since", old)
	if err != nil {
		t.Fatal(err)
	}
	var errs bytes.Buffer
	code, err := e.Finished(&scanPlan{}, thisWeek(), &errs)
	if err != nil || code != exitOK {
		t.Fatalf("exit %d, %v", code, err)
	}
	want := "1 new, 1 fixed since " + old + "\n" +
		"  new: [HIGH] leak-git-config - https://a.test/.git/config\n" +
		"  fixed: [CRITICAL] leak-dotenv - https://a.test/.env\n"
	if errs.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", errs.String(), want)
	}

	// -q keeps only the summary line.
	errs.Reset()
	p := &scanPlan{}
	p.o.quiet = true
	if _, err := e.Finished(p, thisWeek(), &errs); err != nil || errs.String() != "1 new, 1 fixed since "+old+"\n" {
		t.Errorf("quiet: %q, %v", errs.String(), err)
	}
}

func TestReportExtensionFailOnNew(t *testing.T) {
	old, _ := diffFixtures(t)
	for level, want := range map[string]int{"high": exitFindings, "low": exitFindings, "critical": exitOK} {
		e, err := planned(t, "--since", old, "--fail-on-new", level)
		if err != nil {
			t.Fatal(err)
		}
		if code, err := e.Finished(&scanPlan{}, thisWeek(), io.Discard); err != nil || code != want {
			t.Errorf("--fail-on-new %s: exit %d, want %d (%v)", level, code, want, err)
		}
	}
	// Nothing new: a finding that was already there doesn't fail the build.
	cur := saveReport(t, "same.json", finding("xmlrpc", "/xmlrpc.php", engine.Low), finding("leak-git-config", "/.git/config", engine.High))
	e, err := planned(t, "--since", cur, "--fail-on-new", "info")
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := e.Finished(&scanPlan{}, thisWeek(), io.Discard); code != exitOK {
		t.Errorf("nothing new: exit %d", code)
	}
}

func TestReportExtensionPlanErrors(t *testing.T) {
	var ue usageError
	if _, err := planned(t, "--fail-on-new", "high"); !errors.As(err, &ue) || !strings.Contains(err.Error(), "needs --since") {
		t.Errorf("--fail-on-new alone: %v", err)
	}
	if _, err := planned(t, "--since", "x.json", "--fail-on-new", "severe"); !errors.As(err, &ue) {
		t.Errorf("bad level: %v", err)
	}
	if _, err := planned(t, "--since", "/nonexistent/last-week.json"); err == nil || errors.As(err, &ue) {
		t.Errorf("missing file should be a plain error (exit 3): %v", err)
	}
	e, err := planned(t)
	if err != nil {
		t.Fatal(err)
	}
	var errs bytes.Buffer
	if code, err := e.Finished(&scanPlan{}, thisWeek(), &errs); code != exitOK || err != nil || errs.Len() != 0 {
		t.Errorf("without --since: exit %d, %v, %q", code, err, errs.String())
	}
	if !strings.Contains(e.Help(), "--since <file>") || !strings.Contains(e.Help(), "--fail-on-new <level>") {
		t.Errorf("help:\n%s", e.Help())
	}
}
