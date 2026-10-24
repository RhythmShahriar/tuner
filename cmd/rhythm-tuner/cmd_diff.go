// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/tuner/diff"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/report"
)

const diffUsage = `Usage:
  rhythm tuner diff <old.json> <new.json> [flags]

Compares two JSON reports (rhythm tuner scan --json) and lists the findings
that are new and the ones that were fixed. Findings match by fingerprint, so
staging compares with production and a moved folder with its old copy. A
finding counts as new when its severity changed or it has a new advisory.

Flags:
      --json               the comparison as JSON
      --md                 the comparison as Markdown
      --fail-on-new <level>
                           exit 1 if a new finding is at or above this severity

Exit codes: 0 ok · 1 new findings at --fail-on-new · 2 usage error · 3 a report couldn't be read
`

func init() {
	registerCommand(command{Name: "diff", Summary: "compare two JSON reports: what is new and what was fixed", Run: cmdDiff})
}

// cmdDiff runs rhythm tuner diff. It is registered with registerCommand
// (cmd/rhythm-tuner/extend.go) once that lands; until then only tests call
// it.
func cmdDiff(args []string, stdout, stderr io.Writer) int {
	var (
		asJSON, asMD bool
		failOnNew    string
	)
	flags := flag.NewFlagSet("diff", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&asJSON, "json", false, "")
	flags.BoolVar(&asMD, "md", false, "")
	flags.StringVar(&failOnNew, "fail-on-new", "", "")
	pos, err := cli.ParseInterspersed(flags, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, diffUsage)
			return exitOK
		}
		fmt.Fprintf(stderr, "rhythm tuner: %v\n\n%s", err, diffUsage)
		return exitUsage
	}
	if len(pos) != 2 {
		fmt.Fprintf(stderr, "rhythm tuner: diff takes two JSON reports, the old one first\n\n%s", diffUsage)
		return exitUsage
	}
	if asJSON && asMD {
		fmt.Fprintln(stderr, "rhythm tuner: pick one of --json and --md")
		return exitUsage
	}
	level, err := severityFlag("--fail-on-new", failOnNew)
	if err != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitUsage
	}
	before, err := loadReports(pos[0])
	if err != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitError
	}
	after, err := loadReports(pos[1])
	if err != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitError
	}

	res := diff.Compare(before, after)
	write := diff.WriteText
	switch {
	case asJSON:
		write = diff.WriteJSON
	case asMD:
		write = diff.WriteMarkdown
	}
	if err := write(stdout, res, pos[0]); err != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitError
	}
	if level != "" && res.NewAtOrAbove(level) {
		return exitFindings
	}
	return exitOK
}

// severityFlag checks a severity flag's value; "" means the flag is off.
func severityFlag(name, v string) (engine.Severity, error) {
	s := engine.Severity(v)
	if v != "" && s.Rank() < 0 {
		return "", fmt.Errorf("%s %q: want one of %v", name, v, engine.Severities)
	}
	return s, nil
}

// loadReports reads a saved JSON report: one target's, or a batch.
func loadReports(path string) ([]report.Report, error) {
	reports, _, err := readSaved(path)
	return reports, err
}

// readSaved reads a saved JSON report with the targets it couldn't scan.
func readSaved(path string) ([]report.Report, []report.TargetError, error) {
	f, err := os.Open(path) //nolint:gosec // the user names the report to read
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	reports, failed, err := report.ReadJSON(f)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return reports, failed, nil
}
