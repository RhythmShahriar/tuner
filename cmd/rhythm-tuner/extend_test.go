// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/report"
)

// testExtension stays inert unless its flags are set, so every other scan
// test runs with it registered and unchanged.
type testExtension struct {
	addTarget string
	exit      int
	fail      bool
	finished  int // how many reports Finished saw, or -1
}

func (e *testExtension) Help() string {
	return "Test extension:\n      --test-add <url>     scan this target too\n"
}

func (e *testExtension) Flags(fs *flag.FlagSet) {
	*e = testExtension{finished: -1}
	fs.StringVar(&e.addTarget, "test-add", "", "")
	fs.IntVar(&e.exit, "test-exit", 0, "")
	fs.BoolVar(&e.fail, "test-fail", false, "")
}

func (e *testExtension) Plan(p *scanPlan) error {
	if e.addTarget != "" {
		p.targets = append(p.targets, e.addTarget)
		p.write.Many = true
	}
	if e.exit < 0 {
		return usagef("--test-exit must be >= 0")
	}
	return nil
}

func (e *testExtension) Finished(_ *scanPlan, reports []report.Report, _ io.Writer) (int, error) {
	e.finished = len(reports)
	if e.fail {
		return 0, fmt.Errorf("test extension failed")
	}
	return e.exit, nil
}

var testExt = &testExtension{finished: -1}

func init() {
	registerCommand(command{Name: "test-echo", Alias: "te", Summary: "print the arguments (tests only)",
		Run: func(args []string, stdout, _ io.Writer) int {
			fmt.Fprintln(stdout, strings.Join(args, " "))
			return 7
		}})
	registerScanExtension(testExt)
}

func TestRegisteredCommand(t *testing.T) {
	for _, name := range []string{"test-echo", "te"} {
		if code, out, _ := tuner(t, name, "a", "b"); code != 7 || out != "a b\n" {
			t.Errorf("%s: exit %d, out %q", name, code, out)
		}
	}
	_, out, _ := tuner(t, "--help")
	if !strings.Contains(out, "  rhythm tuner test-echo             print the arguments (tests only)\n") {
		t.Errorf("usage does not list the command:\n%s", out)
	}
}

func TestRegisterCommandTwicePanics(t *testing.T) {
	for _, name := range []string{"test-echo", "scan", "ls"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("registering %q again did not panic", name)
				}
			}()
			registerCommand(command{Name: name})
		}()
	}
}

func TestScanExtension(t *testing.T) {
	_, out, _ := tuner(t, "scan", "--help")
	if !strings.Contains(out, "Test extension:\n      --test-add <url>") {
		t.Errorf("scan help lacks the extension section:\n%s", out)
	}

	// Plan adds a target; Finished sees both reports and raises the exit.
	a, b := cleanSite(t), cleanSite(t)
	code, out, errs := tuner(t, "scan", a.URL, "--json", "--test-add", b.URL, "--test-exit", "5")
	if code != 5 || testExt.finished != 2 {
		t.Fatalf("exit %d, Finished saw %d reports: %s", code, testExt.finished, errs)
	}
	var reps []struct{ Target string }
	if err := json.Unmarshal([]byte(out), &reps); err != nil || len(reps) != 2 {
		t.Errorf("want 2 reports, got %v:\n%.300s", err, out)
	}

	// A lower extension exit never hides the scan's own.
	if code, _, _ := tuner(t, "scan", leakySite(t).URL, "--json", "--fail-on", "high", "--test-exit", "0"); code != exitFindings {
		t.Errorf("exit %d, want %d", code, exitFindings)
	}
	if code, _, errs := tuner(t, "scan", a.URL, "--json", "--test-fail"); code != exitError || !strings.Contains(errs, "test extension failed") {
		t.Errorf("failing Finished: exit %d: %s", code, errs)
	}
	if code, _, _ := tuner(t, "scan", a.URL, "--test-exit", "-1"); code != exitUsage {
		t.Errorf("Plan usage error: exit %d, want %d", code, exitUsage)
	}
	if code, _, _ := tuner(t, "scan", a.URL, "--json"); code != exitOK || testExt.finished != 1 {
		t.Errorf("inert extension: exit %d, Finished saw %d", code, testExt.finished)
	}
}

// Run as rhythm-tuner, subcommand help and errors name rhythm-tuner, and
// the usage list stays within 80 columns with each command's arguments.
func TestSubcommandsUseTheirName(t *testing.T) {
	t.Setenv(invokedAsEnv, "")
	old := argv0
	argv0 = "/usr/local/bin/rhythm-tuner"
	defer func() { argv0 = old }()

	var out, errs bytes.Buffer
	if code := run([]string{"diff", "only-one.json"}, &out, &errs); code != exitUsage ||
		!strings.HasPrefix(errs.String(), "rhythm-tuner: diff takes two JSON reports") || strings.Contains(errs.String(), "rhythm tuner") {
		t.Errorf("diff error: %d %q", code, errs.String())
	}
	out.Reset()
	if code := run([]string{"watch", "--help"}, &out, &errs); code != exitOK || !strings.Contains(out.String(), "rhythm-tuner watch -l <file>") || strings.Contains(out.String(), "rhythm tuner") {
		t.Errorf("watch help: %d\n%s", code, out.String())
	}

	out.Reset()
	usage(&out)
	for _, want := range []string{"rhythm-tuner diff <old.json> <new.json>", "rhythm-tuner explain <id>", "rhythm-tuner update [--clear | --prefetch <dir|url>...]"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("usage lacks %q", want)
		}
	}
	usageList, _, _ := strings.Cut(out.String(), "\nOutput:")
	for _, line := range strings.Split(usageList, "\n") {
		if len(line) > usageWidth {
			t.Errorf("%d columns: %q", len(line), line)
		}
	}
}
