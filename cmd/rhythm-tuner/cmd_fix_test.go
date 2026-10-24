// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fix(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	old := fixStdin
	fixStdin = strings.NewReader(stdin)
	t.Cleanup(func() { fixStdin = old })
	var out, errb bytes.Buffer
	code = cmdFix(args, &out, &errb)
	return code, out.String(), errb.String()
}

// A report from a real scan of the leaky site goes straight into fix.
func TestFixFromScanReport(t *testing.T) {
	report := filepath.Join(t.TempDir(), "report.json")
	if code, _, errOut := tuner(t, "scan", leakySite(t).URL, "--id", "leak-dotenv", "--no-vulns", "--no-check-updates", "-o", report); code != exitOK {
		t.Fatalf("scan exit %d: %s", code, errOut)
	}
	code, out, errOut := fix(t, "", report, "--server", "nginx")
	if code != exitOK || errOut != "" {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"# Tuner fix bundle for nginx, from rhythm-tuner dev.\n# 1 snippet for 1 finding.",
		"\n# leak-dotenv\n#   http://127.0.0.1:",
		"/.env\nlocation ~ /\\.(?!well-known) { deny all; }\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, rawSecret) {
		t.Error("bundle shows the secret")
	}
}

func TestFixStdinAndDryRun(t *testing.T) {
	data, err := os.ReadFile("../../fixgen/testdata/batch.json")
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut := fix(t, string(data), "--dry-run", "-", "--server", "apache")
	if code != exitOK || !strings.HasPrefix(out, "apache bundle: 5 snippets for 9 findings\n") || strings.Contains(out, "Require all denied") {
		t.Errorf("exit %d %s:\n%s", code, errOut, out)
	}
}

func TestFixErrors(t *testing.T) {
	dir := t.TempDir()
	notJSON := filepath.Join(dir, "report.md")
	if err := os.WriteFile(notJSON, []byte("# Tuner report\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{nil, exitUsage, "fix needs at least one JSON report"},
		{[]string{"r.json"}, exitUsage, "fix needs --server nginx or --server apache"},
		{[]string{"-", "--server", "caddy"}, exitUsage, `unknown server "caddy": want nginx or apache`},
		{[]string{"--bogus"}, exitUsage, "flag provided but not defined"},
		{[]string{filepath.Join(dir, "missing.json"), "--server", "nginx"}, exitError, "missing.json: open"},
		{[]string{notJSON, "--server", "nginx"}, exitError, "report.md: not a JSON report; write one with: rhythm tuner scan <url> --json"},
	} {
		stdin := `{"schema": "rhythm-tuner/v0", "findings": []}`
		code, _, errOut := fix(t, stdin, tc.args...)
		if code != tc.code || !strings.Contains(errOut, tc.want) {
			t.Errorf("%v: exit %d %q, want %d %q", tc.args, code, errOut, tc.code, tc.want)
		}
	}
	if code, out, _ := fix(t, "", "--help"); code != exitOK || !strings.Contains(out, "rhythm tuner fix <report.json>...") {
		t.Errorf("help: exit %d %q", code, out)
	}
}
