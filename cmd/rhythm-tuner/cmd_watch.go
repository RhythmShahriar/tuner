// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/watch"
)

// watchUsage is the help for rhythm tuner watch.
const watchUsage = `Usage:
  rhythm tuner watch -l <file> --every <interval> [flags] [-- <scan flags>]
  rhythm tuner watch -l <file> --at <HH:MM> [flags] [-- <scan flags>]
  rhythm tuner watch <url>... --every <interval> [flags]

Scans a list of sites on a schedule, keeps each run's JSON report and
compares every run with the one before: "2 new, 1 fixed since the last
run". Each run is its own rhythm tuner scan process, so the watch stays
small however long it runs. Ctrl-C or SIGTERM lets a scan in progress
finish, then stops; a second Ctrl-C stops the scan too.

Schedule:
      --every <interval>    run now, then every interval, e.g. 24h or 6h
                            (at least 1m)
      --at <HH:MM>          run every day at this local time; several
                            times separated by commas, e.g. 02:00,14:00
      --now                 with --at, also run once right away
      --once                run once now and exit with the scan's exit code
                            (for cron and CI)

Targets and state:
  -l, --list <file>         sites to scan, one per line (read on every run)
      --name <name>         the watch's name (default: the list file's name,
                            or the first site's host)
      --dir <dir>           folder for reports and logs (default: your user
                            cache folder, rhythm/tuner/watch/<name>)
      --keep <n>            runs to keep, oldest deleted first (default 30;
                            0 keeps all)
      --exec <binary>       Tuner binary to run (default: this one)

Passed to every scan:
      --notify <url>        tell this destination about new findings
                            (repeatable; see rhythm tuner scan --help);
                            the first run sends every finding
      --notify-min <level>
      --fail-on-new <level> exit 1 if a new finding is at or above this
                            severity (from the second run on)
  -- <scan flags>           everything after -- goes to scan as written,
                            e.g. -- --profile quick --rate 2

After every scan:
      --html                also render the report as HTML next to it

Each run writes <dir>/<UTC time>.json and the scan's output to
<dir>/<UTC time>.log, then prints one line such as:
  2026-10-24 02:00 AEST: 3 sites, 12 findings (1 critical, 2 high, 9 low);
  2 new, 1 fixed since the last run; report <dir>/20261023T160000Z.json
Two runs of one watch never overlap: a lock in its folder turns the
second away.

Examples:
  rhythm tuner watch -l clients.txt --at 02:00 --fail-on-new high --html
  rhythm tuner watch example.com --every 6h -- --profile quick
  rhythm tuner watch -l clients.txt --once
`

// watchKeep is how many runs a watch keeps by default: a month of daily runs.
const watchKeep = 30

// watchOwned are the scan flags the watch sets itself. Passing them
// after -- would break the run-to-run comparison.
var watchOwned = []string{"o", "output", "json", "jsonl", "sarif", "md", "l", "list", "stdin", "since", "notify-all-first"}

// watchPassed are the scan flags the watch has itself: it passes
// --fail-on-new only on a run with an earlier report and adds
// --notify-all-first to --notify on a run without one.
var watchPassed = []string{"fail-on-new", "notify", "notify-min"}

// init registers rhythm tuner watch.
func init() {
	registerCommand(command{Name: "watch", Args: "-l <file> --every <interval>", Summary: "scan a site list on a schedule and say what changed", Run: cmdWatch})
}

// cmdWatch runs scans on a schedule; see watchUsage.
func cmdWatch(args []string, stdout, stderr io.Writer) int {
	w, once, err := planWatch(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, named(watchUsage))
			return exitOK
		}
		fmt.Fprintf(stderr, "rhythm tuner: %v\nrun 'rhythm tuner watch --help' for its flags\n", err)
		return exitUsage
	}
	w.Log = stdout

	if once {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		run, err := w.RunOnce(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "rhythm tuner:", err)
			if errors.Is(err, watch.ErrScanUsage) {
				return exitUsage
			}
			return exitError
		}
		fmt.Fprintln(stdout, run.Line())
		if run.Exit < 0 {
			return exitCanceled
		}
		return run.Exit
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		<-sig
		fmt.Fprintln(stderr, "rhythm tuner: stopping once the current scan finishes; press Ctrl-C again to stop it now")
		cancel()
		<-sig
		w.Abort()
	}()
	fmt.Fprintf(stdout, "Watching the sites in %s, %s; reports go to %s\n", w.List, describeSchedule(w.Schedule), w.Dir)
	if err := w.Run(ctx); err != nil {
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		if errors.Is(err, watch.ErrScanUsage) {
			return exitUsage
		}
		return exitError
	}
	fmt.Fprintln(stdout, "Stopped.")
	return exitOK
}

// planWatch parses watch's flags into a Watcher. once reports --once.
func planWatch(args []string) (w *watch.Watcher, once bool, err error) {
	var extra []string
	if i := slices.Index(args, "--"); i >= 0 {
		args, extra = args[:i], args[i+1:]
	}
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var list, at, name, dir, exe, notifyMin, failOnNew string
	var every time.Duration
	var now, html bool
	var notify cli.RepeatFlag
	fs.StringVar(&list, "l", "", "")
	fs.StringVar(&list, "list", "", "")
	fs.DurationVar(&every, "every", 0, "")
	fs.StringVar(&at, "at", "", "")
	fs.BoolVar(&now, "now", false, "")
	fs.BoolVar(&once, "once", false, "")
	fs.StringVar(&name, "name", "", "")
	fs.StringVar(&dir, "dir", "", "")
	keep := fs.Int("keep", watchKeep, "")
	fs.StringVar(&exe, "exec", "", "")
	fs.Var(&notify, "notify", "")
	fs.StringVar(&notifyMin, "notify-min", "", "")
	fs.StringVar(&failOnNew, "fail-on-new", "", "")
	fs.BoolVar(&html, "html", false, "")
	targets, err := cli.ParseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, false, err
		}
		return nil, false, errors.New(updateFlagError(err, fs))
	}

	var sched watch.Schedule
	sched.Every = every
	if at != "" {
		if sched.At, err = watch.ParseAt(at); err != nil {
			return nil, false, err
		}
	}
	if !once {
		if err := sched.Validate(); err != nil {
			return nil, false, err
		}
	} else if every != 0 || at != "" || now {
		return nil, false, errors.New("--once runs a single scan; drop --every, --at and --now, or drop --once")
	}
	if now && at == "" {
		return nil, false, errors.New("--now goes with --at; --every already starts with a run")
	}
	if *keep < 0 {
		return nil, false, fmt.Errorf("--keep %d: want 0 or more", *keep)
	}
	for _, lvl := range []struct{ flag, v string }{{"notify-min", notifyMin}, {"fail-on-new", failOnNew}} {
		if lvl.v != "" && engine.Severity(lvl.v).Rank() < 0 {
			return nil, false, fmt.Errorf("--%s %q: want one of %v", lvl.flag, lvl.v, engine.Severities)
		}
	}
	for _, a := range extra {
		n := strings.TrimLeft(a, "-")
		n, _, _ = strings.Cut(n, "=")
		if !strings.HasPrefix(a, "-") {
			continue
		}
		if slices.Contains(watchOwned, n) {
			return nil, false, fmt.Errorf("the watch sets %s itself; drop it after --", a)
		}
		if slices.Contains(watchPassed, n) {
			return nil, false, fmt.Errorf("%s is a watch flag; put it before --", a)
		}
	}

	switch {
	case list != "" && len(targets) > 0:
		return nil, false, errors.New("pick one of -l <file> and sites on the command line")
	case list == "" && len(targets) == 0:
		return nil, false, errors.New("watch needs sites: -l <file>, or sites after watch, e.g. rhythm tuner watch example.com --every 24h")
	}
	for _, t := range targets {
		if isLocalPath(t) {
			return nil, false, fmt.Errorf("%s: watch scans sites by URL; for a site folder use cron with rhythm tuner scan", t)
		}
		if _, _, err := engine.ParseTarget(t); err != nil {
			return nil, false, err
		}
	}
	if list != "" {
		if list, err = filepath.Abs(list); err != nil {
			return nil, false, err
		}
		if _, err := os.Stat(list); err != nil { //nolint:gosec // the user's own -l file
			return nil, false, fmt.Errorf("can't read the site list: %w", err)
		}
	}
	if name == "" {
		name = defaultWatchName(list, targets)
	}
	name = safeWatchName(name)
	if dir == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return nil, false, fmt.Errorf("no user cache folder (%w); pass --dir", err)
		}
		dir = filepath.Join(cache, "rhythm", "tuner", "watch", name)
	}
	if dir, err = filepath.Abs(dir); err != nil {
		return nil, false, err
	}
	if exe == "" {
		if exe, err = os.Executable(); err != nil {
			return nil, false, fmt.Errorf("can't find this binary (%w); pass --exec", err)
		}
	}
	if len(targets) > 0 {
		// The scan reads sites from a file either way, so the watch
		// command line and a list file behave the same.
		if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // the user's own --dir
			return nil, false, err
		}
		list = filepath.Join(dir, watchSitesName)
		if err := os.WriteFile(list, []byte(strings.Join(targets, "\n")+"\n"), 0o600); err != nil { //nolint:gosec // inside the user's own --dir
			return nil, false, err
		}
	}

	// --notify and --fail-on-new need --since. A run with no earlier
	// report sends every finding (--notify-all-first) and fails on
	// nothing new: there is nothing to compare with yet.
	var pass []string
	for _, n := range notify {
		pass = append(pass, "--notify", n)
	}
	if notifyMin != "" {
		pass = append(pass, "--notify-min", notifyMin)
	}
	first := slices.Clone(pass)
	if len(notify) > 0 {
		first = append(first, "--notify-all-first")
	}
	if failOnNew != "" {
		pass = append(pass, "--fail-on-new", failOnNew)
	}
	return &watch.Watcher{
		Exe: exe, List: list, Extra: extra, Dir: dir,
		Schedule: sched, RunNow: now, Keep: *keep, HTML: html,
		PassSince:  true, // scan has --since, so each run marks its own changes
		SinceFlags: pass, FirstFlags: first,
	}, once, nil
}

// defaultWatchName names a watch after its list file ("clients" for
// clients.txt) or the first site's host.
func defaultWatchName(list string, targets []string) string {
	if list != "" {
		return strings.TrimSuffix(filepath.Base(list), filepath.Ext(list))
	}
	if u, _, err := engine.ParseTarget(targets[0]); err == nil {
		return u.Hostname()
	}
	return "watch"
}

// watchSitesName is the list file a watch writes in its folder for the
// sites given on its command line. The name is the watch's own, so it
// never replaces a sites.txt the user keeps there.
const watchSitesName = "watch-sites.txt"

// unsafeName matches runs of characters a folder name made from a site
// must not hold: a site's host or path can't name a folder outside
// the watch's own.
var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// windowsDevice matches the names Windows keeps for devices, such as CON
// or com1.txt, which can't name a folder there.
var windowsDevice = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$`)

// safeWatchName keeps a watch name usable as one folder name everywhere.
func safeWatchName(name string) string {
	name = strings.TrimRight(strings.TrimLeft(unsafeName.ReplaceAllString(name, "-"), ".-"), ". ")
	if name == "" {
		return "watch"
	}
	if windowsDevice.MatchString(name) {
		name += "-watch"
	}
	return name
}

// describeSchedule reads "every 24h" or "daily at 02:00, 14:00".
func describeSchedule(s watch.Schedule) string {
	if s.Every > 0 {
		d := s.Every.String() // 24h0m0s, 1h30m0s, 1m30s
		if strings.HasSuffix(d, "m0s") {
			d = strings.TrimSuffix(d, "0s")
		}
		if strings.HasSuffix(d, "h0m") {
			d = strings.TrimSuffix(d, "0m")
		}
		return "every " + d
	}
	times := make([]string, len(s.At))
	for i, t := range s.At {
		times[i] = t.String()
	}
	return "daily at " + strings.Join(times, ", ")
}
