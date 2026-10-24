// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/RhythmShahriar/tuner/checks"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fixgen"
)

// fixStdin is where `fix -` reads a report; tests replace it.
var fixStdin io.Reader = os.Stdin

// maxReport caps a report file; a batch of a few thousand sites is well
// under it.
const maxReport = 64 << 20

// cmdFix runs `rhythm tuner fix <report.json>... --server nginx|apache`:
// one config bundle for every finding in the reports that a server rule
// fixes. It prints to stdout only; it never edits a file, reloads a
// server or makes a request.
//
// It is registered with registerCommand (cmd/rhythm-tuner/extend.go) once
// that lands; until then only tests call it.
func cmdFix(args []string, stdout, stderr io.Writer) int {
	var (
		server string
		dryRun bool
	)
	flags := flag.NewFlagSet("fix", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&server, "server", "", "")
	flags.BoolVar(&dryRun, "dry-run", false, "")
	files, err := parseInterspersed(flags, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, fixUsage)
			return exitOK
		}
		fmt.Fprintf(stderr, "rhythm tuner: %v\n\n%s", err, fixUsage)
		return exitUsage
	}
	switch {
	case len(files) == 0:
		fmt.Fprintf(stderr, "rhythm tuner: fix needs at least one JSON report\n\n%s", fixUsage)
		return exitUsage
	case server == "":
		fmt.Fprintf(stderr, "rhythm tuner: fix needs --server nginx or --server apache\n\n%s", fixUsage)
		return exitUsage
	}

	var findings []fixgen.Finding
	for _, name := range files {
		data, err := readReport(name)
		if err == nil {
			var fs []fixgen.Finding
			fs, err = fixgen.ParseReport(data)
			findings = append(findings, fs...)
		}
		if err != nil {
			fmt.Fprintf(stderr, "rhythm tuner: %s: %v\n", name, err)
			return exitError
		}
	}
	// The built-in checks supply the snippet for their own IDs whatever
	// the report says, which also covers reports from before fix_server.
	builtIn, err := engine.LoadChecks(checks.FS)
	if err != nil {
		fmt.Fprintln(stderr, "rhythm tuner: loading checks:", err)
		return exitError
	}
	b, err := fixgen.Build(findings, server, builtIn)
	if err != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitUsage
	}
	if dryRun {
		err = b.WritePlan(stdout)
	} else {
		err = b.Write(stdout, version)
	}
	if err != nil {
		return exitError
	}
	return exitOK
}

// readReport reads a report file, or stdin for "-".
func readReport(name string) ([]byte, error) {
	r := fixStdin
	if name != "-" {
		f, err := os.Open(name) //nolint:gosec // the user names the report to read
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxReport+1))
	if err == nil && len(data) > maxReport {
		err = fmt.Errorf("larger than %d MB", maxReport>>20)
	}
	return data, err
}

const fixUsage = `Usage:
  rhythm tuner fix <report.json>... --server nginx|apache [--dry-run]

Builds one config bundle from JSON reports (rhythm tuner scan --json):
the nginx or Apache snippets that fix the findings, each snippet once,
commented with the checks and URLs it fixes. Snippets for Tuner's own
checks come from this version, not from the report, so reports from older
versions work too. A snippet the report carries for any other check is
marked as taken from the report. It prints to stdout and changes nothing: review the bundle,
add it to your server config and test it (nginx -t or apachectl -t).
Use - to read a report from stdin.

Flags:
      --server <name>      nginx or apache
      --dry-run            list the snippets the bundle would hold, without
                           the config text
`
