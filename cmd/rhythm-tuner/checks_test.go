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
	if code, out, _ := checksCmd("test", dir); code != exitOK || !strings.Contains(out, "ok  leak-old-backup  1 positive, 3 negative") ||
		!strings.HasSuffix(out, "\nThe check in "+dir+" passed (4 cases).\n") {
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
		!strings.Contains(out, "1 of 1 check in "+dir+" failed.") {
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
	missing := filepath.Join(t.TempDir(), "nope")
	file := filepath.Join(t.TempDir(), "x.yaml")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
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
		{[]string{"test", missing}, exitUsage, "rhythm tuner: checks test: " + missing + ": no such directory"},
		{[]string{"lint", missing}, exitUsage, "rhythm tuner: checks lint: " + missing + ": no such directory"},
		{[]string{"test", file}, exitUsage, "rhythm tuner: checks test: " + file + ": not a directory"},
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

func TestChecksExportNuclei(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nuclei")
	code, out, errOut := checksCmd("export", "--nuclei", dir, "--no-check-updates")
	if code != exitOK || !regexp.MustCompile(`^Wrote \d+ Nuclei templates and README.md to `+regexp.QuoteMeta(dir)+`\.\n`).MatchString(out) ||
		!regexp.MustCompile(`(?m)^  tls-cert-expired +TLS conditions need a TLS probe`).MatchString(out) ||
		!strings.HasSuffix(out, "Run them with: nuclei -t "+dir+" -u <url>\n") {
		t.Fatalf("exit %d %s:\n%s", code, errOut, out)
	}
	tmpl, err := os.ReadFile(filepath.Join(dir, "tuner-leak-dotenv.yaml"))
	if err != nil || !bytes.Contains(tmpl, []byte("id: tuner-leak-dotenv\n")) {
		t.Errorf("template: %v\n%s", err, tmpl)
	}
	if _, err := os.Stat(filepath.Join(dir, "tuner-tls-cert-expired.yaml")); err == nil {
		t.Error("skipped check was written")
	}
	readme, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil || !bytes.Contains(readme, []byte("MIT License")) {
		t.Errorf("README: %v\n%s", err, readme)
	}

	// --id narrows the export and a run replaces its own files.
	code, out, _ = checksCmd("export", "--nuclei", dir, "--no-check-updates", "--id", "leak-git*")
	if code != exitOK || !strings.HasPrefix(out, "Wrote 3 Nuclei templates and README.md to ") || strings.Contains(out, "Skipped") {
		t.Errorf("--id: exit %d:\n%s", code, out)
	}
}

// Export replaces a symlink in the target folder instead of writing
// through it and counts a single skipped check as one.
func TestChecksExportSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tuner-leak-dotenv.yaml", "README.md"} {
		if err := os.Symlink(victim, filepath.Join(dir, name)); err != nil {
			t.Skip("no symlinks:", err)
		}
	}
	code, out, errOut := checksCmd("export", "--nuclei", dir, "--no-check-updates", "--id", "leak-dotenv,tls-cert-expired")
	if code != exitOK || !strings.HasPrefix(out, "Wrote 1 Nuclei template and README.md") || !strings.Contains(out, "Skipped 1 check a template can't express:") {
		t.Fatalf("exit %d %s:\n%s", code, errOut, out)
	}
	if data, _ := os.ReadFile(victim); string(data) != "keep\n" {
		t.Errorf("export wrote through a symlink: %q", data)
	}
	for _, name := range []string{"tuner-leak-dotenv.yaml", "README.md"} {
		fi, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
			t.Errorf("%s: %v %v", name, fi, err)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".tuner-export-*")); len(left) > 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

// A check ID with path separators never names a file outside --nuclei.
func TestChecksExportUnsafeID(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "checks")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	check := "id: ../escaped\nname: X\nseverity: low\nrequest: {path: [/x]}\nmatch: {all: [{regex: x}]}\n"
	if err := os.WriteFile(filepath.Join(src, "x.yaml"), []byte(check), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "out", "nuclei")
	code, stdout, errOut := checksCmd("export", "--nuclei", out, "--checks", src)
	if code != exitOK || !strings.Contains(stdout, "Wrote 0 Nuclei templates") ||
		!strings.Contains(stdout, `"../escaped"  the ID is not lowercase words joined by hyphens`) {
		t.Fatalf("exit %d %s:\n%s", code, errOut, stdout)
	}
	for _, p := range []string{filepath.Join(root, "out", "escaped.yaml"), filepath.Join(root, "out", "tuner-..", "escaped.yaml")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("wrote %s", p)
		}
	}
	entries, _ := os.ReadDir(out)
	if len(entries) != 1 || entries[0].Name() != "README.md" {
		t.Errorf("out holds %v, want README.md only", entries)
	}
}

func TestChecksExportUsage(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "checks export needs --nuclei <dir>"},
		{[]string{"--nuclei", "x", "extra"}, `checks export takes no arguments, got "extra"`},
		{[]string{"--bogus"}, "checks export: flag provided but not defined: -bogus"},
		{[]string{"--nuclei", "x", "--id", "nope-*"}, `no check matches "nope-*"`},
	} {
		if code, _, errOut := checksCmd(append([]string{"export", "--no-check-updates"}, tc.args...)...); code != exitUsage || !strings.Contains(errOut, tc.want) {
			t.Errorf("%v: exit %d, stderr %q", tc.args, code, errOut)
		}
	}
	if code, out, _ := checksCmd("export", "--help"); code != exitOK || !strings.HasPrefix(out, "Usage:\n  rhythm tuner checks export --nuclei <dir>") {
		t.Errorf("help: exit %d:\n%s", code, out)
	}
}
