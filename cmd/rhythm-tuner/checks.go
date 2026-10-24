// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/RhythmShahriar/tuner/checks"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/engine/checktest"
	"github.com/RhythmShahriar/tuner/export"
)

// listChecks prints the checks a scan with the same flags would run, or
// runs one of the subcommands: new, test, lint and export.
func listChecks(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "new":
			return checksNew(args[1:], stdout, stderr)
		case "test":
			return checksTest(args[1:], stdout, stderr)
		case "lint":
			return checksLint(args[1:], stdout, stderr)
		case "export":
			return checksExport(args[1:], stdout, stderr)
		}
	}
	var (
		profile, severity, dir             string
		tags, excludeTags, ids, excludeIDs listFlag
		asJSON, offline, noUpdates         bool
	)
	flags := flag.NewFlagSet("checks", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&profile, "profile", string(engine.ProfileDeep), "")
	flags.StringVar(&severity, "severity", "", "")
	flags.StringVar(&dir, "checks", "", "")
	flags.Var(&tags, "tags", "")
	flags.Var(&excludeTags, "exclude-tags", "")
	flags.Var(&ids, "id", "")
	flags.Var(&excludeIDs, "exclude-id", "")
	flags.BoolVar(&asJSON, "json", false, "")
	flags.BoolVar(&offline, "offline", false, "")
	flags.BoolVar(&noUpdates, "no-check-updates", false, "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, checksUsage)
			return exitOK
		}
		fmt.Fprintf(stderr, "rhythm tuner: %v\n\n%s", err, checksUsage)
		return exitUsage
	}

	ua := fmt.Sprintf("rhythm-tuner/%s (+https://rythm.sh/tuner)", version)
	set, err := loadCheckSet(dir, !noUpdates, offline, ua, nil)
	if err != nil {
		fmt.Fprintln(stderr, "rhythm tuner: loading checks:", err)
		return exitError
	}
	for _, w := range set.warnings {
		fmt.Fprintln(stderr, "rhythm tuner:", w)
	}
	sel, err := engine.Select(set.checks, engine.Selector{
		Profile: engine.Profile(profile), Tags: tags, ExcludeTags: excludeTags,
		IDs: ids, ExcludeIDs: excludeIDs, MinSeverity: engine.Severity(severity),
	})
	if err != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitUsage
	}

	if asJSON {
		type row struct {
			ID       string          `json:"id"`
			Name     string          `json:"name"`
			Severity engine.Severity `json:"severity"`
			Profile  engine.Profile  `json:"profile"`
			Tags     []string        `json:"tags"`
			Requires []string        `json:"requires,omitempty"`
			Paths    []string        `json:"paths"`
		}
		var rows []row
		for _, c := range sel {
			rows = append(rows, row{c.ID, c.Name, c.Severity, c.Profile, c.Tags, c.Requires, c.Request.Path})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			return exitError
		}
		return exitOK
	}

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tPROFILE\tTAGS\tNAME")
	for _, c := range sel {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", c.ID, c.Severity, c.Profile, strings.Join(c.Tags, ","), c.Name)
	}
	if err := tw.Flush(); err != nil {
		return exitError
	}
	fmt.Fprintf(stdout, "\nUsing %s.\n", set.describe(dir))
	noun := "checks"
	if len(sel) == 1 {
		noun = "check"
	}
	fmt.Fprintf(stdout, "%d %s, plus vulnerability matching for core, plugins, themes, PHP and\n"+
		"nginx/Apache (vuln-*, wp-components-*, *-eol), which scans skip with --no-vulns.\n", len(sel), noun)
	return exitOK
}

const checksUsage = `Usage:
  rhythm tuner checks [flags]
  rhythm tuner checks new <id> [dir]   write a new check and its fixtures
  rhythm tuner checks test [dir]       run checks against their fixtures
  rhythm tuner checks lint [dir]       check checks against the house rules
  rhythm tuner checks export --nuclei <dir>   write checks as Nuclei templates

Lists the checks a scan with the same flags would run. Unlike scan, the
profile defaults to deep, so every check is listed. test and lint read the
built-in checks when no directory is given; neither needs Go.

Flags:
      --profile <name>     quick, default or deep (default "deep")
      --tags <list>        only checks with these tags
      --exclude-tags <list>
      --id <list>          only these checks; globs allowed
      --exclude-id <list>
      --severity <level>   skip checks below this severity
      --checks <dir>       list checks from a directory
      --json               machine-readable output
      --offline            use only a cached check pack
      --no-check-updates   ignore check packs; list the built-in checks
`

// checksDir is the checks test and lint read: dir, or the built-in
// checks when dir is empty.
func checksDir(dir string) (fs.FS, string, error) {
	if dir == "" {
		return checks.FS, "built-in checks", nil
	}
	// A missing directory is a bad argument, not a failing check, and
	// os.DirFS would only say "stat .".
	switch st, err := os.Stat(dir); { //nolint:gosec // the user names the directory to read
	case errors.Is(err, fs.ErrNotExist):
		return nil, "", fmt.Errorf("%s: no such directory", dir)
	case err != nil:
		return nil, "", err
	case !st.IsDir():
		return nil, "", fmt.Errorf("%s: not a directory", dir)
	}
	return os.DirFS(dir), dir, nil
}

// plural is "1 check" or "n checks".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// oneDir parses a subcommand's arguments: at most one directory, no flags
// but --help.
func oneDir(name string, args []string, usage string, stdout, stderr io.Writer) (dir string, exit int, ok bool) {
	for _, a := range args {
		switch {
		case a == "-h" || a == "--help":
			fmt.Fprint(stdout, usage)
			return "", exitOK, false
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(stderr, "rhythm tuner: checks %s: unknown flag %s\n\n%s", name, a, usage)
			return "", exitUsage, false
		}
	}
	if len(args) > 1 {
		fmt.Fprintf(stderr, "rhythm tuner: checks %s takes at most one directory\n\n%s", name, usage)
		return "", exitUsage, false
	}
	if len(args) == 1 {
		dir = args[0]
	}
	return dir, exitOK, true
}

// checksTest runs every check in a directory against its fixtures with
// the same runner as go test, so pack and fork contributors need no Go.
func checksTest(args []string, stdout, stderr io.Writer) int {
	dir, exit, ok := oneDir("test", args, checksTestUsage, stdout, stderr)
	if !ok {
		return exit
	}
	fsys, name, err := checksDir(dir)
	if err != nil {
		fmt.Fprintf(stderr, "rhythm tuner: checks test: %v\n", err)
		return exitUsage
	}
	results := checktest.Run(fsys)

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	var checksSeen, failed, cases int
	for i := 0; i < len(results); {
		// Results come grouped by check, in check order.
		j := i
		for j < len(results) && results[j].Check == results[i].Check {
			j++
		}
		group := results[i:j]
		i = j
		if group[0].Check == "" { // the set itself failed to load
			failed++
			fmt.Fprintf(tw, "FAIL\t%s\n", strings.Join(group[0].Problems, "; "))
			continue
		}
		checksSeen++
		var pos, neg int
		var lines []string
		for _, r := range group {
			if r.Case != "" {
				cases++
				if r.Positive {
					pos++
				} else {
					neg++
				}
			}
			for _, p := range r.Problems {
				lines = append(lines, fmt.Sprintf("\t  %s: %s", r, p))
			}
			for _, l := range r.Leaks {
				note := " (not yet enforced)"
				if checktest.StrictOutput {
					note = ""
				}
				lines = append(lines, fmt.Sprintf("\t  %s: %s%s", r, l, note))
			}
		}
		status := "ok"
		if slices.ContainsFunc(group, func(r checktest.Result) bool { return r.Failed(checktest.StrictOutput) }) {
			status = "FAIL"
			failed++
		}
		fmt.Fprintf(tw, "%s\t%s\t%d positive, %d negative\n", status, group[0].Check, pos, neg)
		for _, l := range lines {
			fmt.Fprintln(tw, l)
		}
	}
	if err := tw.Flush(); err != nil {
		return exitError
	}
	if failed > 0 {
		fmt.Fprintf(stdout, "\n%d of %s in %s failed.\n", failed, plural(max(checksSeen, failed), "check"), name)
		return exitFindings
	}
	if checksSeen == 1 {
		fmt.Fprintf(stdout, "\nThe check in %s passed (%s).\n", name, plural(cases, "case"))
		return exitOK
	}
	fmt.Fprintf(stdout, "\nAll %s in %s passed (%s).\n", plural(checksSeen, "check"), name, plural(cases, "case"))
	return exitOK
}

const checksTestUsage = `Usage:
  rhythm tuner checks test [dir]

Runs every check in dir (default: the built-in checks) against its
fixtures, <name>_test.yaml next to each check: mock sites on 127.0.0.1 it
must fire on (positive) and stay quiet on (negative). Exits 1 when a check
fails. No request leaves this machine.
`

// checksLint reports checks that break the rules built-in checks follow.
func checksLint(args []string, stdout, stderr io.Writer) int {
	dir, exit, ok := oneDir("lint", args, checksLintUsage, stdout, stderr)
	if !ok {
		return exit
	}
	fsys, name, err := checksDir(dir)
	if err != nil {
		fmt.Fprintf(stderr, "rhythm tuner: checks lint: %v\n", err)
		return exitUsage
	}
	issues := checktest.Lint(fsys)
	for _, i := range issues {
		fmt.Fprintln(stdout, i)
	}
	if len(issues) > 0 {
		noun := "issues"
		if len(issues) == 1 {
			noun = "issue"
		}
		fmt.Fprintf(stdout, "\n%d %s in %s.\n", len(issues), noun, name)
		return exitFindings
	}
	fmt.Fprintf(stdout, "No issues in %s.\n", name)
	return exitOK
}

const checksLintUsage = `Usage:
  rhythm tuner checks lint [dir]

Checks every check in dir (default: the built-in checks) against the rules
built-in checks follow: a lower-case ID with a known prefix (leak-, wp-,
php-, laravel-, hdr-, tls-, srv-), GET or HEAD requests only, no payloads
in paths or query strings, not_baseline or a regex, words or magic matcher
on any path but /, an https reference, positive and negative fixtures,
balanced fix_server snippets and at most 30 distinct paths in the quick
profile. Exits 1 when a rule is broken.
`

// checksNew scaffolds a check and its fixtures that pass test and lint
// as they are.
func checksNew(args []string, stdout, stderr io.Writer) int {
	var pos []string
	for _, a := range args {
		switch {
		case a == "-h" || a == "--help":
			fmt.Fprint(stdout, checksNewUsage)
			return exitOK
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(stderr, "rhythm tuner: checks new: unknown flag %s\n\n%s", a, checksNewUsage)
			return exitUsage
		}
		pos = append(pos, a)
	}
	if len(pos) < 1 || len(pos) > 2 {
		fmt.Fprintf(stderr, "rhythm tuner: checks new takes an ID and an optional directory\n\n%s", checksNewUsage)
		return exitUsage
	}
	id, dir := pos[0], "."
	if len(pos) == 2 {
		dir = pos[1]
	}
	check, fixture, err := checktest.Scaffold(id)
	if err != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitUsage
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // checks are source files, readable like the rest of a repository
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitError
	}
	checkPath, fixturePath := filepath.Join(dir, id+".yaml"), filepath.Join(dir, id+"_test.yaml")
	for _, p := range []string{checkPath, fixturePath} {
		if _, err := os.Lstat(p); err == nil { //nolint:gosec // the directory the user named
			fmt.Fprintf(stderr, "rhythm tuner: %s already exists; nothing written\n", p)
			return exitError
		}
	}
	for _, f := range []struct {
		path string
		data []byte
	}{{checkPath, check}, {fixturePath, fixture}} {
		// O_EXCL: never replace a file that appeared since the check above.
		out, err := os.OpenFile(f.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // as for MkdirAll
		if err == nil {
			_, err = out.Write(f.data)
			if cerr := out.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			fmt.Fprintln(stderr, "rhythm tuner:", err)
			return exitError
		}
	}
	fmt.Fprintf(stdout, "Wrote %s and %s.\nReplace the TODOs, then run:\n  rhythm tuner checks test %s\n  rhythm tuner checks lint %s\n",
		checkPath, fixturePath, dir, dir)
	return exitOK
}

const checksNewUsage = `Usage:
  rhythm tuner checks new <id> [dir]

Writes <dir>/<id>.yaml (a check to fill in) and <dir>/<id>_test.yaml (its
fixtures). dir defaults to the current folder. Both pass checks test and
checks lint as written. It never replaces a file. The ID is lower-case
words joined by hyphens and starts with leak-, wp-, php-, laravel-, hdr-,
tls- or srv-, e.g. leak-old-backup.
`

// checksExport writes the checks a scan would use as Nuclei templates,
// one file per check plus a README with the license. It reports the
// checks a template can't express.
func checksExport(args []string, stdout, stderr io.Writer) int {
	var (
		out, dir           string
		tags, ids          listFlag
		offline, noUpdates bool
	)
	flags := flag.NewFlagSet("checks export", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&out, "nuclei", "", "")
	flags.StringVar(&dir, "checks", "", "")
	flags.Var(&tags, "tags", "")
	flags.Var(&ids, "id", "")
	flags.BoolVar(&offline, "offline", false, "")
	flags.BoolVar(&noUpdates, "no-check-updates", false, "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, checksExportUsage)
			return exitOK
		}
		fmt.Fprintf(stderr, "rhythm tuner: checks export: %v\n\n%s", err, checksExportUsage)
		return exitUsage
	}
	switch {
	case flags.NArg() > 0:
		fmt.Fprintf(stderr, "rhythm tuner: checks export takes no arguments, got %q\n\n%s", flags.Arg(0), checksExportUsage)
		return exitUsage
	case out == "":
		fmt.Fprintf(stderr, "rhythm tuner: checks export needs --nuclei <dir>\n\n%s", checksExportUsage)
		return exitUsage
	}

	ua := fmt.Sprintf("rhythm-tuner/%s (+https://rythm.sh/tuner)", version)
	set, err := loadCheckSet(dir, !noUpdates, offline, ua, nil)
	if err != nil {
		fmt.Fprintln(stderr, "rhythm tuner: loading checks:", err)
		return exitError
	}
	for _, w := range set.warnings {
		fmt.Fprintln(stderr, "rhythm tuner:", w)
	}
	sel, err := engine.Select(set.checks, engine.Selector{Profile: engine.ProfileDeep, Tags: tags, IDs: ids})
	if err != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitUsage
	}

	opts := export.Options{Version: version}
	templates := export.Nuclei(sel, opts)
	if err := os.MkdirAll(out, 0o755); err != nil { //nolint:gosec // templates are meant to be shared, like checks
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitError
	}
	files := map[string][]byte{"README.md": export.NucleiREADME(templates, opts, checks.License)}
	var written int
	var skipped []export.Template
	for _, t := range templates {
		if t.Skipped != "" {
			skipped = append(skipped, t)
			continue
		}
		files[t.File] = t.Data
		written++
	}
	for name, data := range files {
		// export skips IDs that can't be file names; this guard keeps any
		// later change from writing outside out.
		if !filepath.IsLocal(name) || filepath.Base(name) != name {
			fmt.Fprintf(stderr, "rhythm tuner: checks export: refusing to write %q outside %s\n", name, out)
			return exitError
		}
		if err := replaceFile(filepath.Join(out, name), data); err != nil {
			fmt.Fprintln(stderr, "rhythm tuner:", err)
			return exitError
		}
	}

	noun := "templates"
	if written == 1 {
		noun = "template"
	}
	fmt.Fprintf(stdout, "Wrote %d Nuclei %s and README.md to %s.\n", written, noun, out)
	if len(skipped) > 0 {
		fmt.Fprintf(stdout, "Skipped %s a template can't express:\n", plural(len(skipped), "check"))
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		for _, t := range skipped {
			fmt.Fprintf(tw, "  %s\t%s\n", t.DisplayID(), t.Skipped)
		}
		if err := tw.Flush(); err != nil {
			return exitError
		}
	}
	fmt.Fprintf(stdout, "Run them with: nuclei -t %s -u <url>\n", out)
	return exitOK
}

// replaceFile writes data to path through a temporary file and a rename,
// so a symlink already at path is replaced rather than followed: export
// must not overwrite whatever file a link in the target folder points to.
func replaceFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tuner-export-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		// CreateTemp makes the file 0600; templates are meant to be shared.
		err = os.Chmod(tmp.Name(), 0o644) //nolint:gosec // as for MkdirAll
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
	}
	return err
}

const checksExportUsage = `Usage:
  rhythm tuner checks export --nuclei <dir> [flags]

Writes the checks a scan would use as Nuclei templates, tuner-<id>.yaml in
dir (created if needed), plus README.md with how they differ from Tuner
and the MIT license they ship under. Existing files with those names are
replaced. Checks that need TLS, scheme or cookie conditions, or only the
soft-404 comparison, are listed and left out. Like a scan, it first
refreshes the check pack when the cached one is a day old (waiting at most
10 seconds, through HTTPS_PROXY if set); --offline skips that.

Flags:
      --nuclei <dir>       write Nuclei templates to dir
      --id <list>          only these checks; globs allowed
      --tags <list>        only checks with these tags
      --checks <dir>       export checks from a directory
      --offline            use only a cached check pack
      --no-check-updates   ignore check packs; export the built-in checks
`
