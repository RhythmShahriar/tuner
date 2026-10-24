// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/tuner/report"
)

const reportUsage = `Usage:
  rhythm tuner report <report.json>... [flags]

Renders saved JSON reports (rhythm tuner scan --json) in another format,
for example as an HTML report for a client. Several files make one report
with a section for each site.

Flags:
      --html               a self-contained HTML report (one file, no scripts)
      --md                 Markdown
      --sarif              SARIF 2.1.0
      --json               JSON (several files merge into one array)
  -o, --output <file>      write to a file (format from the extension)
      --since <file>       an earlier JSON report: the HTML report marks what
                           is new, lists what was fixed and shows how each
                           score moved
      --brand-name <name>  your agency's name on the HTML report
      --brand-logo <file>  your logo on the HTML report (PNG, JPEG or SVG,
                           up to 512 KB)

Exit codes: 0 ok · 2 usage error · 3 a report couldn't be read or written
`

// reportFormats are the formats report renders, in the order its errors
// list them. jsonl streams during a scan, so a saved report can't become it.
var reportFormats = []string{"html", "md", "sarif", "json"}

func init() {
	registerCommand(command{Name: "report", Summary: "render saved JSON reports as HTML, Markdown or SARIF", Run: cmdReport})
}

// cmdReport runs rhythm tuner report. It is registered with
// registerCommand (cmd/rhythm-tuner/extend.go) once that lands; until then
// only tests call it.
func cmdReport(args []string, stdout, stderr io.Writer) int {
	var output, since, brandName, brandLogo string
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	chosen := map[string]*bool{}
	for _, f := range reportFormats {
		chosen[f] = flags.Bool(f, false, "")
	}
	flags.StringVar(&output, "o", "", "")
	flags.StringVar(&output, "output", "", "")
	flags.StringVar(&since, "since", "", "")
	flags.StringVar(&brandName, "brand-name", "", "")
	flags.StringVar(&brandLogo, "brand-logo", "", "")
	pos, err := cli.ParseInterspersed(flags, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, reportUsage)
			return exitOK
		}
		fmt.Fprintf(stderr, "rhythm tuner: %v\n\n%s", err, reportUsage)
		return exitUsage
	}
	usageErr := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "rhythm tuner: "+format+"\n", a...)
		return exitUsage
	}
	if len(pos) == 0 {
		fmt.Fprintf(stderr, "rhythm tuner: report takes one or more JSON reports\n\n%s", reportUsage)
		return exitUsage
	}
	for _, p := range pos {
		// "report a.json --html out.html" reads out.html as a report; say
		// what was meant before it fails as unreadable JSON.
		if f := report.FormatForExt(p); f != "" && f != "json" {
			return usageErr("%s is not a JSON report; to write the report there, use -o %s", report.SafeText(p), report.SafeText(p))
		}
	}

	var format string
	for _, f := range reportFormats {
		if *chosen[f] {
			if format != "" {
				return usageErr("pick one of --html, --md, --sarif and --json")
			}
			format = f
		}
	}
	if format == "" && output != "" {
		if format = report.FormatForExt(output); !slices.Contains(reportFormats, format) {
			return usageErr("can't tell the format of %s; add --html, --md, --sarif or --json", report.SafeText(output))
		}
	}
	if format == "" {
		return usageErr("pick a format: --html, --md, --sarif or --json")
	}
	if since != "" && format != "html" {
		return usageErr("--since marks what is new in the HTML report; for the changes alone, run rhythm tuner diff")
	}
	if err := checkBrand(format == "html", brandName, brandLogo); err != nil {
		return usageErr("%v", err)
	}

	o := report.WriteOptions{Brand: report.Brand{Name: brandName, LogoPath: brandLogo}}
	var reports []report.Report
	for _, p := range pos {
		rs, failed, err := readSaved(p)
		if err != nil {
			fmt.Fprintln(stderr, "rhythm tuner:", err)
			return exitError
		}
		reports, o.Failed = append(reports, rs...), append(o.Failed, failed...)
	}
	o.Many = len(pos) > 1 || len(reports)+len(o.Failed) > 1
	if since != "" {
		if o.Since, err = loadReports(since); err != nil {
			fmt.Fprintln(stderr, "rhythm tuner:", err)
			return exitError
		}
		o.SinceName = sinceName(since)
	}

	if output == "" {
		if err := report.Write(format, stdout, reports, o); err != nil {
			fmt.Fprintln(stderr, "rhythm tuner:", err)
			return exitError
		}
		return exitOK
	}
	if err := writeFile(output, format, reports, o); err != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		return exitError
	}
	fmt.Fprintf(stderr, "Report written to %s\n", report.SafeText(output))
	return exitOK
}

// writeFile writes reports to path in format.
func writeFile(path, format string, reports []report.Report, o report.WriteOptions) error {
	f, err := os.Create(path) //nolint:gosec // the user names the file to write
	if err != nil {
		return err
	}
	if err := report.Write(format, f, reports, o); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
