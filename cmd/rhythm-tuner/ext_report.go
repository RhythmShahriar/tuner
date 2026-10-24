// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/tuner/diff"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/notify"
	"github.com/RhythmShahriar/tuner/report"
)

// notifyTimeout bounds each notification, so a receiver that hangs
// doesn't hold up a scheduled scan.
const notifyTimeout = 30 * time.Second

func init() { registerScanExtension(&reportExtension{}) }

// reportExtension adds change tracking to rhythm tuner scan: --since
// compares the scan with an earlier JSON report, --fail-on-new fails CI
// only on what is new, --notify sends what is new to chat or email and
// --html writes a client-ready report.
type reportExtension struct {
	since     string
	failOnNew string

	notify         cli.RepeatFlag
	notifyMin      string
	notifyAllFirst bool
	notifyStrict   bool

	html      string
	brandName string
	brandLogo string

	level     engine.Severity
	before    []report.Report
	firstRun  bool // --notify-all-first and no earlier report: all findings are new
	minLevel  engine.Severity
	notifiers []notify.Notifier
	// notifyOptions is for tests, which point the backends at local servers.
	notifyOptions notify.Options
}

func (e *reportExtension) Help() string {
	return `Changes:
      --since <file>       compare with an earlier JSON report and list what
                           is new and what was fixed
      --fail-on-new <level>
                           exit 1 if a new finding is at or above this
                           severity (needs --since; not applied on a
                           first run with --notify-all-first)
      --notify <url>       send new findings to Slack, Discord, a webhook or
                           email (repeatable; needs --since): slack://...,
                           discord://..., webhook+https://... or
                           smtp://user@host:587?to=a@b.c&from=t@b.c with the
                           password in TUNER_SMTP_PASSWORD
      --notify-min <level> lowest severity to send (default high)
      --notify-all-first   with no earlier report, send every finding
      --notify-strict      exit 3 when a notification can't be sent

Client report:
      --html <file>        also write a self-contained HTML report (one file,
                           no scripts; marks what is new with --since)
      --brand-name <name>  your agency's name on the HTML report
      --brand-logo <file>  your logo on the HTML report (PNG, JPEG or SVG,
                           up to 512 KB)`
}

// Flags registers the flags and clears what an earlier scan in the same
// process left behind: repeatable flags append, so --notify would pile up.
func (e *reportExtension) Flags(fs *flag.FlagSet) {
	*e = reportExtension{notifyOptions: e.notifyOptions}
	fs.StringVar(&e.since, "since", "", "")
	fs.StringVar(&e.failOnNew, "fail-on-new", "", "")
	fs.Var(&e.notify, "notify", "")
	fs.StringVar(&e.notifyMin, "notify-min", "", "")
	fs.BoolVar(&e.notifyAllFirst, "notify-all-first", false, "")
	fs.BoolVar(&e.notifyStrict, "notify-strict", false, "")
	fs.StringVar(&e.html, "html", "", "")
	fs.StringVar(&e.brandName, "brand-name", "", "")
	fs.StringVar(&e.brandLogo, "brand-logo", "", "")
}

// Plan checks the flags and reads the old report before the scan starts,
// so a typo in the file name or a notification URL doesn't cost a whole
// scan.
func (e *reportExtension) Plan(p *scanPlan) error {
	var err error
	if e.level, err = severityFlag("--fail-on-new", e.failOnNew); err != nil {
		return usageError{Msg: err.Error()}
	}
	if err := e.planNotify(); err != nil {
		return err
	}
	if err := checkBrand(e.html != "" || p.format == "html", e.brandName, e.brandLogo); err != nil {
		return err
	}
	// -o client.html gets the brand too.
	p.write.Brand = report.Brand{Name: e.brandName, LogoPath: e.brandLogo}
	if e.since == "" {
		if e.level != "" {
			return usagef("--fail-on-new needs --since <file>, the report to compare with")
		}
		e.firstRun = len(e.notifiers) > 0
		return nil
	}
	e.before, err = loadReports(e.since)
	if err != nil && e.notifyAllFirst && errors.Is(err, fs.ErrNotExist) {
		// The first scheduled run: the report it will compare with next
		// time doesn't exist yet.
		e.firstRun = true
		return nil
	}
	return err
}

// planNotify checks the notification flags and URLs. Errors name a URL
// by its scheme and host only: the rest is the webhook's secret.
func (e *reportExtension) planNotify() error {
	lowest, err := severityFlag("--notify-min", e.notifyMin)
	if err != nil {
		return usageError{Msg: err.Error()}
	}
	if len(e.notify) == 0 {
		switch {
		case e.notifyMin != "":
			return usagef("--notify-min needs --notify <url>")
		case e.notifyAllFirst:
			return usagef("--notify-all-first needs --notify <url>")
		case e.notifyStrict:
			return usagef("--notify-strict needs --notify <url>")
		}
		return nil
	}
	if e.since == "" && !e.notifyAllFirst {
		return usagef("--notify needs --since <file>, so it sends only what is new (add --notify-all-first to send every finding when there is no earlier report)")
	}
	e.minLevel = cmp.Or(lowest, engine.High)
	o := e.notifyOptions
	o.SMTPPassword = os.Getenv("TUNER_SMTP_PASSWORD")
	for _, raw := range e.notify {
		n, err := notify.Parse(raw, o)
		if err != nil {
			return usagef("--notify: %v", err)
		}
		e.notifiers = append(e.notifiers, n)
	}
	return nil
}

// checkBrand checks the branding flags, reading the logo now so a bad
// one fails before any work is done. html says an HTML report is asked for.
func checkBrand(html bool, name, logo string) error {
	if !html && (name != "" || logo != "") {
		return usagef("--brand-name and --brand-logo only go on the HTML report (--html)")
	}
	if logo != "" {
		if _, err := report.LogoDataURI(logo); err != nil {
			return usageError{Msg: err.Error()}
		}
	}
	return nil
}

// Finished prints what changed to stderr, so it never mixes into a report
// on stdout, then sends the notifications. It exits 1 for --fail-on-new and
// 3 for a notification that failed under --notify-strict.
func (e *reportExtension) Finished(p *scanPlan, reports []report.Report, stderr io.Writer) (int, error) {
	if e.html != "" {
		o := p.write // the scan's failed targets and version reach the HTML file too
		o.Brand = report.Brand{Name: e.brandName, LogoPath: e.brandLogo}
		if !e.firstRun {
			o.Since, o.SinceName = e.before, sinceName(e.since)
		}
		if err := writeFile(e.html, "html", reports, o); err != nil {
			return exitError, err
		}
		if !p.o.quiet {
			fmt.Fprintf(stderr, "HTML report written to %s\n", e.html)
		}
	}
	if e.since == "" && !e.firstRun {
		return exitOK, nil
	}
	res := diff.Compare(e.before, reports)
	since := e.since
	if e.firstRun {
		since = ""
		if !p.o.quiet {
			fmt.Fprintln(stderr, "no previous report; sending all findings")
		}
	} else {
		fmt.Fprintln(stderr, res.Summary(e.since))
		// The notes stay under -q: without them "0 new, 12 fixed" from a
		// blocked scan reads like good news.
		for _, n := range res.Incomplete {
			fmt.Fprintln(stderr, "  "+n)
		}
		if !p.o.quiet {
			for _, n := range res.New {
				fmt.Fprintln(stderr, "  new: "+n.Line())
			}
			for _, f := range res.Fixed {
				fmt.Fprintln(stderr, "  fixed: "+f.Line())
			}
			for _, f := range res.NotSeen {
				fmt.Fprintln(stderr, "  not seen: "+f.Line())
			}
		}
	}
	code := exitOK
	// On a first run nothing is new yet: everything would fail the build
	// the first time a schedule runs, before there is anything to compare.
	if e.level != "" && !e.firstRun && res.NewAtOrAbove(e.level) {
		code = exitFindings
	}
	if len(e.notifiers) > 0 && !e.send(res, since, reports, p.o.quiet, stderr) && e.notifyStrict {
		code = exitError
	}
	return code, nil
}

// send delivers the message to every notifier and reports whether all of
// them took it. A failure is a warning: the scan itself went fine.
func (e *reportExtension) send(res diff.Result, since string, reports []report.Report, quiet bool, stderr io.Writer) bool {
	version := ""
	if len(reports) > 0 {
		version = reports[0].Version
	}
	msg := notify.Build(res, since, e.minLevel, version)
	// A scan that didn't finish still notifies, with its notes: a blocked
	// weekly scan that stays silent looks like a clean week.
	if len(msg.Findings) == 0 && len(msg.Incomplete) == 0 {
		if !quiet {
			fmt.Fprintf(stderr, "nothing new at %s or above, so no notification\n", e.minLevel)
		}
		return true
	}
	ok := true
	for _, n := range e.notifiers {
		ctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
		err := n.Send(ctx, msg)
		cancel()
		switch {
		case err != nil:
			ok = false
			fmt.Fprintf(stderr, "rhythm tuner: warning: could not notify %s: %v\n", n, report.SafeText(err.Error()))
		case !quiet:
			noun := "findings"
			if len(msg.Findings) == 1 {
				noun = "finding"
			}
			fmt.Fprintf(stderr, "notified %s: %d %s\n", n, len(msg.Findings), noun)
		}
	}
	return ok
}

// sinceName is how a client report names the earlier report: its file
// name, not the folders on the agency's machine.
func sinceName(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}
