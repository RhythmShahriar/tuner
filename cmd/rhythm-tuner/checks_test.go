// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func checksCmd(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = listChecks(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestChecksTestBuiltIn(t *testing.T) {
	code, out, errOut := checksCmd("test")
	if code != exitOK || !regexp.MustCompile(`(?m)^ok +leak-dotenv +6 positive, 4 negative$`).MatchString(out) ||
		!strings.Contains(out, "\nAll ") || !strings.Contains(out, "checks in built-in checks passed (") {
		t.Errorf("exit %d %s:\n%s", code, errOut, out)
	}
}

func TestChecksLintBuiltIn(t *testing.T) {
	if code, out, _ := checksCmd("lint"); code != exitOK || out != "No issues in built-in checks.\n" {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

// checks new writes a check that passes test and lint straight away, and
// test and lint then catch what a contributor breaks.
func TestChecksNewTestLint(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "leaks")
	code, out, errOut := checksCmd("new", "leak-old-backup", dir)
	check := filepath.Join(dir, "leak-old-backup.yaml")
	if code != exitOK || !strings.Contains(out, "Wrote "+check+" and "+filepath.Join(dir, "leak-old-backup_test.yaml")+".\n") {
		t.Fatalf("new: exit %d %s:\n%s", code, errOut, out)
	}
	if code, out, _ := checksCmd("test", dir); code != exitOK || !strings.Contains(out, "ok  leak-old-backup  1 positive, 3 negative") {
		t.Errorf("test: exit %d:\n%s", code, out)
	}
	if code, out, _ := checksCmd("lint", dir); code != exitOK || out != "No issues in "+dir+".\n" {
		t.Errorf("lint: exit %d:\n%s", code, out)
	}

	// Never replaces a file.
	if code, _, errOut := checksCmd("new", "leak-old-backup", dir); code != exitError || !strings.Contains(errOut, "already exists; nothing written") {
		t.Errorf("second new: exit %d %s", code, errOut)
	}

	// Drop the guard: lint complains and the catch-all fixture fails.
	data, _ := os.ReadFile(check)
	data = bytes.Replace(data, []byte("    - not_baseline: true\n"), nil, 1)
	if err := os.WriteFile(check, data, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ = checksCmd("test", dir)
	if code != exitFindings || !strings.Contains(out, "FAIL  leak-old-backup") ||
		!strings.Contains(out, `negative "catch-all that serves the same text for every path": unexpected finding on /old-backup.txt`) ||
		!strings.Contains(out, "1 of 1 checks in "+dir+" failed.") {
		t.Errorf("test after edit: exit %d:\n%s", code, out)
	}
	data = bytes.Replace(data, []byte(`    - words: ["TODO-text-only-the-real-file-has"]`+"\n"), nil, 1)
	if err := os.WriteFile(check, data, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ = checksCmd("lint", dir)
	if code != exitFindings || !strings.Contains(out, "leak-old-backup.yaml: baseline: a path other than / needs not_baseline") || !strings.Contains(out, "\n1 issue in ") {
		t.Errorf("lint after edit: exit %d:\n%s", code, out)
	}
}

func TestChecksSubcommandErrors(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"new"}, exitUsage, "checks new takes an ID and an optional directory"},
		{[]string{"new", "Leak_X", t.TempDir()}, exitUsage, `id "Leak_X": use lower-case words joined by hyphens`},
		{[]string{"new", "acme-x", t.TempDir()}, exitUsage, "start it with one of hdr-, laravel-, leak-, php-, srv-, tls-, wp-"},
		{[]string{"new", "--force", "leak-x"}, exitUsage, "checks new: unknown flag --force"},
		{[]string{"test", "a", "b"}, exitUsage, "checks test takes at most one directory"},
		{[]string{"lint", "--json"}, exitUsage, "checks lint: unknown flag --json"},
	} {
		code, _, errOut := checksCmd(tc.args...)
		if code != tc.code || !strings.Contains(errOut, tc.want) {
			t.Errorf("%v: exit %d %q, want %d %q", tc.args, code, errOut, tc.code, tc.want)
		}
	}
	for _, sub := range []string{"new", "test", "lint"} {
		if code, out, _ := checksCmd(sub, "--help"); code != exitOK || !strings.Contains(out, "rhythm tuner checks "+sub) {
			t.Errorf("%s --help: exit %d %q", sub, code, out)
		}
	}
	// A directory without checks fails to load.
	code, out, _ := checksCmd("test", t.TempDir())
	if code != exitFindings || !strings.Contains(out, "FAIL  no checks found") {
		t.Errorf("empty dir: exit %d:\n%s", code, out)
	}
	if code, out, _ := checksCmd("lint", t.TempDir()); code != exitFindings || !strings.Contains(out, "checks: load: no checks found") {
		t.Errorf("empty dir lint: exit %d:\n%s", code, out)
	}
}
