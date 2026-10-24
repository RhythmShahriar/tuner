// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const goldenURLWorkflow = `# Scans the site at https://staging.example.com with Tuner.
# The job fails on findings at or above fail-on. Written by
# rhythm tuner init ci; every input: https://github.com/RhythmShahriar/rhythm/wiki/Tuner-CI
name: tuner
on:
  push:
    branches: [main, master]
  pull_request:
  # Weekly too, so newly published vulnerabilities show up without a push.
  schedule:
    - cron: "17 4 * * 1"
  workflow_dispatch:

permissions:
  contents: read
  security-events: write # upload tuner.sarif to code scanning

jobs:
  tuner:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      # @v0 follows every v0.x release. To pin one exactly, use its commit
      # SHA and keep the version in a comment:
      #   uses: RhythmShahriar/tuner@<commit sha> # <release tag>
      - uses: RhythmShahriar/tuner@v0
        with:
          target: "https://staging.example.com"
          fail-on: high
          sarif: true
          # Pull requests from forks can't write code scanning alerts.
          sarif-upload: ${{ github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository }}
`

const goldenFolderWorkflow = `# Scans the site folder ./public with Tuner.
# The job fails on findings at or above fail-on. Written by
# rhythm tuner init ci; every input: https://github.com/RhythmShahriar/rhythm/wiki/Tuner-CI
name: tuner
on:
  push:
    branches: [main, master]
  pull_request:
  # Weekly too, so newly published vulnerabilities show up without a push.
  schedule:
    - cron: "17 4 * * 1"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  tuner:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      # @v0 follows every v0.x release. To pin one exactly, use its commit
      # SHA and keep the version in a comment:
      #   uses: RhythmShahriar/tuner@<commit sha> # <release tag>
      - uses: RhythmShahriar/tuner@v0
        with:
          target: "./public"
          fail-on: medium
`

// repo makes a git repository (just a .git folder) with the given folders.
func repo(t *testing.T, dirs ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range append([]string{".git"}, dirs...) {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func runInit(t *testing.T, dir string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = initCI(args, dir, &out, &errb)
	return code, out.String(), errb.String()
}

func readWorkflow(t *testing.T, root string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "tuner.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// writeGolden saves a generated workflow to $TUNER_INIT_CI_OUT, where CI
// runs actionlint over it (make init-ci-lint).
func writeGolden(t *testing.T, name, body string) {
	t.Helper()
	if dir := os.Getenv("TUNER_INIT_CI_OUT"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInitCIURL(t *testing.T) {
	root := repo(t)
	code, out, errOut := runInit(t, root, "--target", "https://staging.example.com", "--sarif")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	got := readWorkflow(t, root)
	if got != goldenURLWorkflow {
		t.Errorf("workflow differs from the golden file:\n%s", got)
	}
	writeGolden(t, "tuner-url.yml", got)
	for _, want := range []string{
		"Wrote .github/workflows/tuner.yml: scans https://staging.example.com, fails on high or worse.",
		"git add .github/workflows/tuner.yml",
		"Security > Code scanning",
		"Scan only sites you own or are authorised to test.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("generated YAML doesn't parse: %v", err)
	}
	if doc["name"] != "tuner" {
		t.Errorf("name = %v", doc["name"])
	}
}

func TestInitCIFolder(t *testing.T) {
	root := repo(t, "public", "docs")
	// Run from a subfolder: the file still goes in the repository root and
	// the target becomes relative to it.
	code, out, errOut := runInit(t, filepath.Join(root, "docs"), "--target", "../public", "--fail-on", "medium")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	got := readWorkflow(t, root)
	if got != goldenFolderWorkflow {
		t.Errorf("workflow differs from the golden file:\n%s", got)
	}
	writeGolden(t, "tuner-folder.yml", got)
	if strings.Contains(out, "authorised") || strings.Contains(out, "Code scanning") {
		t.Errorf("folder output mentions URL or SARIF steps:\n%s", out)
	}
	if !strings.Contains(out, "Wrote ../.github/workflows/tuner.yml: scans ./public, fails on medium or worse.") {
		t.Errorf("output: %s", out)
	}
	if _, err := os.Stat(filepath.Join(root, "docs", ".github")); err == nil {
		t.Error("wrote under the subfolder instead of the repository root")
	}
}

func TestInitCIDetectsSite(t *testing.T) {
	root := repo(t, "wp-content")
	if code, _, errOut := runInit(t, root); code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if got := readWorkflow(t, root); !strings.Contains(got, `target: "."`) || !strings.Contains(got, "the site folder .") {
		t.Errorf("WordPress root not used as the target:\n%s", got)
	}

	// Negative: nothing that looks like a site and no --target.
	empty := repo(t)
	code, _, errOut := runInit(t, empty)
	if code != exitUsage || !strings.Contains(errOut, "pass --target") {
		t.Errorf("exit %d, %q", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(empty, ".github")); err == nil {
		t.Error("wrote something on a usage error")
	}
}

func TestInitCIRefusesOverwrite(t *testing.T) {
	root := repo(t, ".github/workflows")
	path := filepath.Join(root, ".github", "workflows", "tuner.yml")
	if err := os.WriteFile(path, []byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runInit(t, root, "--target", "https://example.com")
	if code != exitUsage || !strings.Contains(errOut, "already exists; pass --force to replace it") {
		t.Errorf("exit %d, %q", code, errOut)
	}
	if got := readWorkflow(t, root); got != "mine\n" {
		t.Errorf("file changed without --force: %q", got)
	}

	if code, _, errOut := runInit(t, root, "--target", "https://example.com", "--force"); code != exitOK {
		t.Fatalf("--force: exit %d: %s", code, errOut)
	}
	if got := readWorkflow(t, root); !strings.Contains(got, `target: "https://example.com"`) {
		t.Errorf("--force didn't replace the file:\n%s", got)
	}
}

func TestInitCIStaysInWorkflows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need extra privileges on Windows")
	}
	outside := t.TempDir()

	// A symlinked tuner.yml would make the write land elsewhere, even with --force.
	root := repo(t, ".github/workflows")
	if err := os.Symlink(filepath.Join(outside, "x.yml"), filepath.Join(root, ".github", "workflows", "tuner.yml")); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runInit(t, root, "--target", "https://example.com", "--force"); code != exitUsage || !strings.Contains(errOut, "symlink") {
		t.Errorf("symlinked file: exit %d, %q", code, errOut)
	}

	// So would a symlinked .github/workflows.
	root = repo(t, ".github")
	if err := os.Symlink(outside, filepath.Join(root, ".github", "workflows")); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runInit(t, root, "--target", "https://example.com"); code != exitUsage || !strings.Contains(errOut, "not a folder") {
		t.Errorf("symlinked folder: exit %d, %q", code, errOut)
	}
	if entries, _ := os.ReadDir(outside); len(entries) > 0 {
		t.Errorf("wrote outside the repository: %v", entries)
	}
}

func TestCITarget(t *testing.T) {
	root := repo(t, "web/site")
	elsewhere := t.TempDir()
	tests := []struct {
		raw, want string
		folder    bool
		err       string
	}{
		{raw: "https://shop.example.com/blog", want: "https://shop.example.com/blog"},
		{raw: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080"},
		{raw: "staging.example.com", want: "https://staging.example.com"},
		{raw: "localhost:8080", want: "https://localhost:8080"},
		{raw: "${{ vars.STAGING_URL }}", want: "${{ vars.STAGING_URL }}"},
		{raw: "web/site", want: "./web/site", folder: true},
		{raw: "./web/site/", want: "./web/site", folder: true},
		{raw: filepath.Join(root, "web"), want: "./web", folder: true},
		{raw: ".", want: ".", folder: true},
		{raw: "https://user:pass@example.com", err: "username or password"},
		{raw: "https://user:pass@example.com", err: "secret with the Action's headers input"},
		{raw: "ftp://example.com", err: "not an http or https URL"},
		{raw: elsewhere, err: "outside the repository"},
		{raw: "./missing", err: "neither a URL nor a folder"},
		{raw: "nothing", err: "neither a URL nor a folder"},
		{raw: "https://example.com\nx", err: "control character"},
	}
	for _, tt := range tests {
		got, folder, err := ciTarget(root, root, tt.raw)
		if tt.err != "" {
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("%q: err %v, want %q", tt.raw, err, tt.err)
			}
			continue
		}
		if err != nil || got != tt.want || folder != tt.folder {
			t.Errorf("%q: got %q folder=%v err=%v, want %q folder=%v", tt.raw, got, folder, err, tt.want, tt.folder)
		}
	}
}

func TestInitUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := cmdInit(nil, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "rhythm tuner init ci") {
		t.Errorf("no args: exit %d, %q", code, errb.String())
	}
	errb.Reset()
	if code := cmdInit([]string{"gitlab"}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), `unknown init target "gitlab"`) {
		t.Errorf("unknown: exit %d, %q", code, errb.String())
	}
	out.Reset()
	if code := cmdInit([]string{"--help"}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "--fail-on <level>") {
		t.Errorf("help: exit %d, %q", code, out.String())
	}

	root := repo(t)
	for _, args := range [][]string{
		{"--target", "https://example.com", "--fail-on", "severe"},
		{"https://example.com"},
		{"--nope"},
	} {
		if code, _, errOut := runInit(t, root, args...); code != exitUsage {
			t.Errorf("%v: exit %d, %q", args, code, errOut)
		}
	}
	if code, out, _ := runInit(t, root, "--target", "https://example.com", "--fail-on", "none"); code != exitOK || !strings.Contains(out, "never fails on findings") {
		t.Errorf("--fail-on none: exit %d, %q", code, out)
	}
	if got := readWorkflow(t, root); !strings.Contains(got, "fail-on: none") {
		t.Errorf("--fail-on none not written:\n%s", got)
	}
}

func TestInitCIWithoutRepo(t *testing.T) {
	dir := t.TempDir()
	if root, ok := repoRoot(dir); ok || root != dir {
		// A temp dir inside a checkout would find that checkout instead.
		t.Skipf("temp dir is inside a repository at %s", root)
	}
	code, _, errOut := runInit(t, dir, "--target", "https://example.com")
	if code != exitOK || !strings.Contains(errOut, "no git repository found") {
		t.Errorf("exit %d, %q", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, ".github", "workflows", "tuner.yml")); err != nil {
		t.Error(err)
	}
}

func TestMajorTag(t *testing.T) {
	for v, want := range map[string]string{
		"0.3.2": "v0", "v0.4.0-rc1": "v0", "1.2.0": "v1", "12.0.1": "v12", "dev": "v0", "": "v0",
	} {
		if got := majorTag(v); got != want {
			t.Errorf("majorTag(%q) = %q, want %q", v, got, want)
		}
	}
}
