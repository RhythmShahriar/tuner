package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/RhythmShahriar/tuner/engine"
)

// listChecks prints the checks a scan with the same flags would run.
func listChecks(args []string, stdout, stderr io.Writer) int {
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

Lists the checks a scan with the same flags would run. Unlike scan, the
profile defaults to deep, so every check is listed.

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
