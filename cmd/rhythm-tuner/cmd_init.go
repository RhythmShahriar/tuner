// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/RhythmShahriar/tuner/engine"
)

// cmdInit runs `rhythm tuner init`. Its one subcommand, ci, writes a GitHub
// Actions workflow that scans with the Tuner Action.
//
// It is registered with registerCommand (cmd/rhythm-tuner/extend.go) once
// that lands; until then only tests call it.
func cmdInit(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, initUsage)
		return exitUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, initUsage)
		return exitOK
	case "ci":
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintln(stderr, "rhythm tuner:", err)
			return exitError
		}
		return initCI(args[1:], wd, stdout, stderr)
	}
	fmt.Fprintf(stderr, "rhythm tuner: unknown init target %q\n\n%s", args[0], initUsage)
	return exitUsage
}

const initUsage = `Usage:
  rhythm tuner init ci [flags]

Writes .github/workflows/tuner.yml, a GitHub Actions workflow that scans
with the Tuner Action on pushes, pull requests and once a week. Run it
anywhere inside the repository; the file goes in the repository root.

Flags:
      --target <url|dir>   the site's URL, or its folder in this repository
                           (default: this folder, when it looks like a site)
      --fail-on <level>    fail the job on findings at or above this severity,
                           or none (default "high")
      --sarif              also upload findings to GitHub code scanning
      --force              replace an existing tuner.yml
`

// initOptions are the flags of init ci.
type initOptions struct {
	target, failOn string
	sarif, force   bool
}

// initCI writes the workflow for the repository that contains dir.
func initCI(args []string, dir string, stdout, stderr io.Writer) int {
	var o initOptions
	flags := flag.NewFlagSet("init ci", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&o.target, "target", "", "")
	flags.StringVar(&o.failOn, "fail-on", string(engine.High), "")
	flags.BoolVar(&o.sarif, "sarif", false, "")
	flags.BoolVar(&o.force, "force", false, "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, initUsage)
			return exitOK
		}
		fmt.Fprintf(stderr, "rhythm tuner: %v\n\n%s", err, initUsage)
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "rhythm tuner: init ci takes no arguments; use --target %s\n", flags.Arg(0))
		return exitUsage
	}
	if o.failOn != "none" && engine.Severity(o.failOn).Rank() < 0 {
		fmt.Fprintf(stderr, "rhythm tuner: --fail-on must be critical, high, medium, low, info or none, not %q\n", o.failOn)
		return exitUsage
	}

	root, inRepo := repoRoot(dir)
	target, folder, err := ciTarget(root, dir, o.target)
	if err != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitUsage
	}

	rel := filepath.Join(".github", "workflows", "tuner.yml")
	path, err := workflowPath(root, o.force)
	if err != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		var ue usageError
		if errors.As(err, &ue) {
			return exitUsage
		}
		return exitError
	}
	body := ciWorkflow(target, folder, o.failOn, o.sarif, majorTag(version))
	//nolint:gosec // a workflow file is committed and read by everyone; 0644 like any source file
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		fmt.Fprintln(stderr, "rhythm tuner: writing the workflow:", err)
		return exitError
	}

	if !inRepo {
		fmt.Fprintf(stderr, "rhythm tuner: no git repository found above %s; wrote the workflow there\n", dir)
	}
	shown := filepath.ToSlash(rel)
	if r, err := filepath.Rel(dir, path); err == nil {
		shown = filepath.ToSlash(r)
	}
	gate := "never fails on findings"
	if o.failOn != "none" {
		gate = "fails on " + o.failOn + " or worse"
	}
	fmt.Fprintf(stdout, "Wrote %s: scans %s, %s.\n\nNext steps:\n", shown, target, gate)
	fmt.Fprintf(stdout, "  1. Review the file, then commit and push it:\n       git add %s\n       git commit -m \"ci: scan with tuner\"\n", shown)
	fmt.Fprintln(stdout, "  2. Watch the first run in the repository's Actions tab.")
	if o.sarif {
		fmt.Fprintln(stdout, "  3. Findings also appear under Security > Code scanning.")
	}
	if !folder {
		fmt.Fprintln(stdout, "\nScan only sites you own or are authorised to test.")
	}
	fmt.Fprintln(stdout, "More: https://github.com/RhythmShahriar/rhythm/wiki/Tuner-CI")
	return exitOK
}

// repoRoot returns the nearest directory at or above dir that holds .git
// (a directory, or a file in worktrees and submodules). Without one it
// returns dir itself and false.
func repoRoot(dir string) (string, bool) {
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return d, true
		}
		if filepath.Dir(d) == d {
			return dir, false
		}
	}
}

// ciTarget turns --target into the value for the Action's target input
// and reports whether it is a folder. Folders become ./ paths relative to
// the repository root, where the workflow's checkout puts them. A GitHub
// expression such as ${{ vars.STAGING_URL }} passes through as it is.
func ciTarget(root, dir, raw string) (target string, folder bool, err error) {
	raw = strings.TrimSpace(raw)
	if strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "", false, usagef("--target has a control character")
	}
	if raw == "" {
		if !looksLikeSite(dir) {
			return "", false, usagef("pass --target with the site's URL or its folder, e.g. --target https://staging.example.com")
		}
		raw = dir
	}
	if strings.HasPrefix(raw, "${{") {
		return raw, false, nil
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return "", false, usagef("--target %s is not an http or https URL", raw)
		}
		if u.User != nil {
			// The workflow is committed, so a password in it is public.
			return "", false, usagef("--target has a username or password; keep credentials out of the workflow (use a secret with args: -H)")
		}
		return u.String(), false, nil
	}

	p := raw
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, p)
	}
	if fi, err := os.Stat(p); err == nil && fi.IsDir() { //nolint:gosec // only checks whether the user's target is a folder
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", false, usagef("%s is outside the repository at %s; CI only sees files in the repository", raw, root)
		}
		// ./ keeps a folder like "public" from being read as a hostname.
		if rel != "." {
			rel = "./" + filepath.ToSlash(rel)
		}
		return rel, true, nil
	}

	// A bare hostname, as the scan command accepts.
	if !strings.ContainsAny(raw, `\ `) && !strings.HasPrefix(raw, ".") {
		if u, err := url.Parse("https://" + raw); err == nil && u.User == nil &&
			(strings.Contains(u.Hostname(), ".") || u.Hostname() == "localhost") {
			return u.String(), false, nil
		}
	}
	return "", false, usagef("--target %s is neither a URL nor a folder in this repository", raw)
}

// looksLikeSite reports whether dir holds a WordPress or PHP site.
func looksLikeSite(dir string) bool {
	for _, name := range []string{"wp-config.php", "wp-includes", "wp-content", "composer.json", "index.php"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

// workflowPath returns root/.github/workflows/tuner.yml, creating the
// folders. It refuses to replace the file without force and refuses any
// symlink on the way, so the write can't land outside .github/workflows.
func workflowPath(root string, force bool) (string, error) {
	dir := root
	for _, part := range []string{".github", "workflows"} {
		dir = filepath.Join(dir, part)
		fi, err := os.Lstat(dir)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := os.Mkdir(dir, 0o755); err != nil { //nolint:gosec // repository folders, like git creates them
				return "", err
			}
		case err != nil:
			return "", err
		case !fi.IsDir():
			return "", usagef("%s is not a folder", dir)
		}
	}
	path := filepath.Join(dir, "tuner.yml")
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return path, nil
	case err != nil:
		return "", err
	case fi.Mode()&fs.ModeSymlink != 0:
		return "", usagef("%s is a symlink; replace it by hand", path)
	case !force:
		return "", usagef("%s already exists; pass --force to replace it", path)
	}
	return path, nil
}

// majorTag is the Action tag that follows this release line: v0 for
// 0.x and dev builds, v1 for 1.x.
func majorTag(v string) string {
	v = strings.TrimPrefix(v, "v")
	major, _, _ := strings.Cut(v, ".")
	if major == "" || strings.Trim(major, "0123456789") != "" {
		return "v0"
	}
	return "v" + major
}

// ciWorkflow renders .github/workflows/tuner.yml.
func ciWorkflow(target string, folder bool, failOn string, sarif bool, tag string) string {
	var b strings.Builder
	what := "the site at " + target
	if folder {
		what = "the site folder " + target
	}
	fmt.Fprintf(&b, `# Scans %s with Tuner.
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
`, what)
	if sarif {
		b.WriteString("  security-events: write # upload tuner.sarif to code scanning\n")
	}
	fmt.Fprintf(&b, `
jobs:
  tuner:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      # @%[1]s follows every %[1]s.x release. To pin one exactly, use its commit
      # SHA and keep the version in a comment:
      #   uses: RhythmShahriar/tuner@<commit sha> # <release tag>
      - uses: RhythmShahriar/tuner@%[1]s
        with:
          target: %[2]s
          fail-on: %[3]s
`, tag, yamlString(target), failOn)
	if sarif {
		b.WriteString(`          sarif: true
          # Pull requests from forks can't write code scanning alerts.
          sarif-upload: ${{ github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository }}
`)
	}
	return b.String()
}

// yamlString quotes s as a YAML double-quoted scalar. GitHub still
// evaluates a ${{ }} expression inside the quotes.
func yamlString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
