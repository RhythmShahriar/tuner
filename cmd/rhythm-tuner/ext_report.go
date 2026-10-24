// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/RhythmShahriar/tuner/diff"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/report"
)

// reportExtension adds change tracking to rhythm tuner scan: --since
// compares the scan with an earlier JSON report and --fail-on-new fails
// CI only on what is new. It has the scanExtension shape from extend.go;
// it is registered with registerScanExtension once that registry is in
// this tree.
type reportExtension struct {
	since     string
	failOnNew string

	level  engine.Severity
	before []report.Report
}

func (e *reportExtension) Help() string {
	return `Changes:
      --since <file>       compare with an earlier JSON report and list what
                           is new and what was fixed
      --fail-on-new <level>
                           exit 1 if a new finding is at or above this
                           severity (needs --since)`
}

func (e *reportExtension) Flags(fs *flag.FlagSet) {
	fs.StringVar(&e.since, "since", "", "")
	fs.StringVar(&e.failOnNew, "fail-on-new", "", "")
}

// Plan checks the flags and reads the old report before the scan starts,
// so a typo in the file name doesn't cost a whole scan.
func (e *reportExtension) Plan(*scanPlan) error {
	var err error
	if e.level, err = severityFlag("--fail-on-new", e.failOnNew); err != nil {
		return usageError{err.Error()}
	}
	if e.since == "" {
		if e.level != "" {
			return usagef("--fail-on-new needs --since <file>, the report to compare with")
		}
		return nil
	}
	e.before, err = loadReports(e.since)
	return err
}

// Finished prints what changed to stderr, so it never mixes into a report
// on stdout, and exits 1 for --fail-on-new.
func (e *reportExtension) Finished(p *scanPlan, reports []report.Report, stderr io.Writer) (int, error) {
	if e.since == "" {
		return exitOK, nil
	}
	res := diff.Compare(e.before, reports)
	fmt.Fprintln(stderr, res.Summary(e.since))
	if !p.o.quiet {
		for _, n := range res.New {
			fmt.Fprintln(stderr, "  new: "+n.Line())
		}
		for _, f := range res.Fixed {
			fmt.Fprintln(stderr, "  fixed: "+f.Line())
		}
	}
	if e.level != "" && res.NewAtOrAbove(e.level) {
		return exitFindings, nil
	}
	return exitOK, nil
}
