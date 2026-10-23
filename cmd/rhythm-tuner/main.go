// rhythm-tuner is the Tuner binary, normally run as `rhythm tuner`.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/x/term"

	"github.com/RhythmShahriar/rhythm/kit"
)

var version = "dev"

// Exit codes.
const (
	exitOK       = 0
	exitFindings = 1 // findings at or above --fail-on
	exitUsage    = 2
	exitError    = 3 // a target couldn't be scanned
	exitCanceled = 130
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		if term.IsTerminal(os.Stdin.Fd()) && term.IsTerminal(os.Stdout.Fd()) {
			return pick(stdout, stderr)
		}
		usage(stdout)
		return exitOK
	}
	switch args[0] {
	case "-h", "--help", "help":
		usage(stdout)
		return exitOK
	case "-v", "--version", "version":
		fmt.Fprintln(stdout, "rhythm-tuner", version)
		return exitOK
	case "scan", "s":
		return scan(args[1:], stdout, stderr)
	case "checks", "ls":
		return listChecks(args[1:], stdout, stderr)
	case "update":
		return cmdUpdate(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "rhythm tuner: unknown command %q\n\n", args[0])
	usage(stderr)
	return exitUsage
}

func usage(w io.Writer) {
	fmt.Fprintln(w, kit.Banner("rhythm tuner", version))
	fmt.Fprint(w, `Find what's out of tune in your WordPress & PHP sites.

Usage:
  rhythm tuner                       interactive picker
  rhythm tuner scan <url>... [flags] scan one or more sites
  rhythm tuner scan <dir> [flags]    scan a site's files on the server
  rhythm tuner checks [flags]        list the checks
  rhythm tuner update [--clear]      refresh vulnerability data now

Output:
      --json               JSON report (an array when scanning several targets)
      --jsonl              one JSON finding per line, streamed as found
      --sarif              SARIF 2.1.0 for GitHub code scanning
      --md                 Markdown for issues and pull requests
  -o, --output <file>      write the report to a file (format from the extension)
                           and keep the live view on the terminal
  -q, --quiet              findings only
      --plain              no color, boxes or glyphs (screen readers, logs)
      --no-color           no color
  -v, --verbose            log every request to stderr

Checks:
      --profile <name>     quick, default or deep (default "default")
      --tags <list>        only checks with these tags, e.g. leak,wordpress
      --exclude-tags <list>
      --id <list>          only these checks; globs allowed, e.g. leak-*
      --exclude-id <list>
      --severity <level>   skip checks below this severity
      --checks <dir>       load checks from a directory
      --no-vulns           skip known-vulnerability matching
      --offline            use cached vulnerability data only

Requests:
      --rate <n>           max requests per second per site (default 5)
  -c, --concurrency <n>    requests in flight per site (default 10)
      --timeout <d>        per-request timeout (default 10s)
      --retries <n>        retries after network errors or 429/503 (default 2)
      --max-time <d>       stop the whole scan after this long
  -A, --user-agent <ua>    User-Agent header
  -H, --header <h>         extra header, "Name: value" (repeatable)
      --cookie <c>         Cookie header, e.g. "session=abc"
      --proxy <url>        http, https or socks5 proxy (HTTPS_PROXY also works)
  -k, --insecure           don't verify TLS certificates

Local scans (when the target is a directory):
      --php <binary>       php to ask for the PHP version (default: php on PATH)
                           Reads WordPress, plugin, theme and composer.lock
                           versions from disk, reviews wp-config.php and finds
                           files that don't belong in a web root. Never runs
                           site code; request flags don't apply.

Batch and CI:
  -l, --list <file>        read targets from a file, one per line
      --stdin              read targets from stdin
      --parallel <n>       sites scanned at once (default 4)
      --fail-on <level>    exit 1 if a finding is at or above this severity
      --baseline <file>    hide findings already in this JSON report

Vulnerability data comes from WPVulnerability (CC0) and api.wordpress.org.
It's cached under your user cache directory and refreshed automatically once
a day; TUNER_VULN_API and TUNER_WPORG_API point Tuner at mirrors. Composer
packages are matched with OSV.dev (TUNER_OSV_API for a mirror).

Exit codes: 0 ok · 1 findings at --fail-on · 2 usage error · 3 scan error · 130 interrupted

Examples:
  rhythm tuner scan example.com
  rhythm tuner scan example.com --profile quick -o report.md
  rhythm tuner scan -l sites.txt --json > results.json
  rhythm tuner scan staging.example.com -H "Authorization: Basic dXNlcjpwYXNz" -k
  rhythm tuner scan example.com --sarif --fail-on high > tuner.sarif
  rhythm tuner scan /var/www/example.com --php /usr/bin/php8.3
`)
}
