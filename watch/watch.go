// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package watch runs Tuner scans of a site list on a schedule and keeps
// each run's JSON report, so every run can say what changed since the
// last one.
//
// Each run executes the Tuner binary as a child process instead of
// scanning in this one. A scan's memory is returned to the OS when the
// child exits, so a watch that runs for months doesn't grow; the
// scan command's flags and extensions apply unchanged.
package watch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RhythmShahriar/tuner/vulns/cache"
)

// Scan exit codes the watch acts on (the scan command's own).
const (
	exitOK       = 0
	exitFindings = 1
	exitUsage    = 2
)

// StateName is the file in the state folder that names the last report
// a later run compares with.
const StateName = "last.json"

// ErrScanUsage means the scan rejected its arguments. Every later run
// would fail the same way, so Run stops.
var ErrScanUsage = errors.New("the scan rejected its flags")

// Watcher runs scans of one site list into one state folder.
type Watcher struct {
	Exe      string   // Tuner binary to run
	List     string   // targets file passed to scan -l
	Extra    []string // more scan flags, passed verbatim
	Dir      string   // state folder: reports, logs, lock and last.json
	Schedule Schedule
	// RunNow starts a daily (At) schedule with a run right away. An
	// interval schedule always starts with one.
	RunNow bool
	// Keep is how many reports to keep; older ones are deleted with
	// their logs. 0 keeps them all.
	Keep int
	// HTML also renders each report with Tuner's report command into
	// an .html file next to it.
	HTML bool
	// PassSince also hands scan --since <last report>, so the scan's own
	// output marks what changed. Leave it off for a scan without that
	// flag: it would reject every run after the first. The digest
	// compares runs either way.
	PassSince bool
	// SinceFlags go to scan only on a run that compares with an earlier
	// report, such as --fail-on-new, which a scan without --since
	// rejects. FirstFlags go only on a run with no earlier report, such
	// as --notify-all-first. Without PassSince every run is a first run.
	SinceFlags []string
	FirstFlags []string
	Clock      Clock     // default RealClock
	Log        io.Writer // one line per run; default io.Discard

	mu    sync.Mutex
	child *os.Process
}

// Run is one finished scan.
type Run struct {
	Started, Finished time.Time
	Report            string // the JSON report, "" when the scan wrote none
	Since             string // the earlier report it was compared with
	HTML              string // the rendered HTML report, if any
	LogFile           string // the scan's terminal output
	Exit              int    // the scan's exit code, -1 if it didn't start or was killed
	Digest            Digest
	// Warning is a problem worth a line that didn't stop the run, such
	// as an HTML render failing.
	Warning string
}

// state is last.json.
type state struct {
	Report   string    `json:"report"` // file name in the state folder
	Finished time.Time `json:"finished"`
	Exit     int       `json:"exit"`
}

func (w *Watcher) clock() Clock {
	if w.Clock == nil {
		return RealClock{}
	}
	return w.Clock
}

func (w *Watcher) logf(format string, a ...any) {
	if w.Log != nil {
		fmt.Fprintf(w.Log, format+"\n", a...)
	}
}

// Run runs scans on the schedule until ctx is done. A run in progress
// when ctx ends is finished, not killed: canceling ctx is the polite
// stop (SIGTERM), Abort the impatient one. It returns nil after a polite
// stop, or the error that made the watch give up.
func (w *Watcher) Run(ctx context.Context) error {
	if err := w.Schedule.Validate(); err != nil {
		return err
	}
	c := w.clock()
	var next time.Time
	if w.Schedule.Every > 0 || w.RunNow {
		next = c.Now()
	} else {
		next = w.Schedule.Next(time.Time{}, c.Now())
		w.logf("Next run %s", next.Format("2006-01-02 15:04 MST"))
	}
	for {
		if err := sleepUntil(ctx, c, next); err != nil {
			return nil //nolint:nilerr // ctx ended between runs: a clean stop
		}
		start := c.Now()
		run, err := w.RunOnce(context.WithoutCancel(ctx))
		switch {
		case errors.Is(err, ErrLocked):
			w.logf("%s: skipped: %v", stamp(start), err)
		case err != nil:
			w.logf("%s: %v", stamp(start), err)
			if errors.Is(err, ErrScanUsage) {
				return err
			}
		default:
			w.logf("%s", run.Line())
		}
		if ctx.Err() != nil {
			return nil
		}
		next = w.Schedule.Next(start, c.Now())
		w.logf("Next run %s", next.Format("2006-01-02 15:04 MST"))
	}
}

// Line is the run's log line: when, the digest, the report and the exit.
func (r Run) Line() string {
	var b strings.Builder
	b.WriteString(stamp(r.Started))
	b.WriteString(": ")
	if r.Report == "" {
		fmt.Fprintf(&b, "scan exited %d without a report; see %s", r.Exit, r.LogFile)
		return b.String()
	}
	b.WriteString(r.Digest.String())
	fmt.Fprintf(&b, "; report %s", r.Report)
	if r.HTML != "" {
		fmt.Fprintf(&b, " and %s", r.HTML)
	}
	if r.Exit != exitOK {
		fmt.Fprintf(&b, " (scan exit %d)", r.Exit)
	}
	if r.Warning != "" {
		b.WriteString("; " + r.Warning)
	}
	return b.String()
}

func stamp(t time.Time) string { return t.Format("2006-01-02 15:04 MST") }

// Args returns the scan arguments for a run writing to report and
// comparing with since (none when since is "" or PassSince is off). A
// comparing run gets SinceFlags, any other run FirstFlags.
func (w *Watcher) Args(report, since string) []string {
	args := []string{"scan", "-l", w.List, "--json", "-o", report}
	if since != "" && w.PassSince {
		args = append(args, "--since", since)
		args = append(args, w.SinceFlags...)
	} else {
		args = append(args, w.FirstFlags...)
	}
	return append(args, w.Extra...)
}

// RunOnce runs one scan now, unless another run of this watch holds the
// lock (ErrLocked). ctx canceling kills the scan; Run passes a context
// that never cancels so a stop finishes the run.
func (w *Watcher) RunOnce(ctx context.Context) (Run, error) {
	if err := os.MkdirAll(w.Dir, 0o700); err != nil {
		return Run{}, err
	}
	unlock, err := Lock(w.Dir)
	if err != nil {
		return Run{}, err
	}
	defer unlock()

	c := w.clock()
	run := Run{Started: c.Now(), Exit: -1}
	var last state
	if err := cache.ReadJSON(filepath.Join(w.Dir, StateName), &last); err == nil && last.Report != "" {
		if p := filepath.Join(w.Dir, filepath.Base(last.Report)); fileExists(p) {
			run.Since = p
		}
	}
	base := w.freeName(run.Started)
	report := filepath.Join(w.Dir, base+".json")
	run.LogFile = filepath.Join(w.Dir, base+".log")

	run.Exit, err = w.exec(ctx, w.Args(report, run.Since), run.LogFile, nil)
	run.Finished = c.Now()
	if err != nil {
		return run, err
	}
	if run.Exit == exitUsage {
		return run, fmt.Errorf("%w (exit 2); see %s", ErrScanUsage, run.LogFile)
	}
	// Only a complete scan becomes the next run's baseline: after an
	// interrupted or failed one (exit 3, 130), the next run compares
	// with the last good report so nothing reads as fixed by mistake.
	good := run.Exit == exitOK || run.Exit == exitFindings
	if fileExists(report) {
		run.Report = report
		d, err := digest(report, run.Since)
		if err != nil {
			run.Warning = err.Error()
			good = false
		}
		run.Digest = d
	}
	if good && run.Report != "" {
		if w.HTML {
			w.renderHTML(ctx, &run, base)
		}
		st := state{Report: base + ".json", Finished: run.Finished, Exit: run.Exit}
		if err := cache.WriteJSON(filepath.Join(w.Dir, StateName), st); err != nil {
			return run, err
		}
	}
	w.prune(run.Report, run.Since)
	return run, nil
}

// renderHTML runs Tuner's report command on the run's JSON. A failure is
// a warning: the JSON report is the record.
func (w *Watcher) renderHTML(ctx context.Context, run *Run, base string) {
	out := filepath.Join(w.Dir, base+".html")
	args := []string{"report", run.Report}
	if run.Since != "" {
		args = append(args, "--since", run.Since)
	}
	args = append(args, "--html")
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // the watch's own state folder
	if err != nil {
		run.Warning = "no HTML report: " + err.Error()
		return
	}
	code, err := w.exec(ctx, args, run.LogFile, f)
	_ = f.Close()
	if err != nil || code != exitOK {
		_ = os.Remove(out)
		run.Warning = fmt.Sprintf("no HTML report (report --html exited %d; see %s)", code, run.LogFile)
		return
	}
	run.HTML = out
}

// exec runs the Tuner binary with args, appending its output to the log
// file; stdout goes to out instead when out isn't nil. It returns the
// exit code. The child is not tied to ctx unless ctx cancels, which only
// RunOnce callers outside Run do.
func (w *Watcher) exec(ctx context.Context, args []string, logFile string, out io.Writer) (int, error) {
	logf, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // the watch's own state folder
	if err != nil {
		return -1, err
	}
	defer func() { _ = logf.Close() }()
	fmt.Fprintf(logf, "$ %s %s\n", filepath.Base(w.Exe), strings.Join(args, " "))
	cmd := exec.Command(w.Exe, args...) //nolint:gosec // the Tuner binary the user configured, with its own flags
	cmd.Stdout, cmd.Stderr = logf, logf
	if out != nil {
		cmd.Stdout = out
	}
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("can't run %s: %w", w.Exe, err)
	}
	w.mu.Lock()
	w.child = cmd.Process
	w.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = cmd.Process.Kill() })
	err = cmd.Wait()
	stop()
	w.mu.Lock()
	w.child = nil
	w.mu.Unlock()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return -1, err
	}
	return cmd.ProcessState.ExitCode(), nil
}

// Abort stops the scan in progress, if any: an interrupt first, so the
// scan writes what it has (marked partial), then a kill where the OS has
// no interrupt.
func (w *Watcher) Abort() {
	w.mu.Lock()
	p := w.child
	w.mu.Unlock()
	if p == nil {
		return
	}
	if err := p.Signal(os.Interrupt); err != nil {
		_ = p.Kill()
	}
}

// freeName returns the report base name for a run starting at t: its UTC
// time, with a suffix if a run in the same second already used it.
func (w *Watcher) freeName(t time.Time) string {
	base := t.UTC().Format("20060102T150405Z")
	name := base
	for i := 2; fileExists(filepath.Join(w.Dir, name+".json")) || fileExists(filepath.Join(w.Dir, name+".log")); i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	return name
}

// runName matches the base name freeName gives a run: its UTC start time,
// with a -N suffix for a second run in the same second. prune only ever
// counts and deletes files with such a name, so anything else in Dir,
// such as a user's own notes or reports, is left alone.
var runName = regexp.MustCompile(`^\d{8}T\d{6}Z(-\d+)?$`)

// prune deletes all but the newest Keep runs' files, never the ones
// named in keep. Only files whose base name is a run stamp count.
func (w *Watcher) prune(keep ...string) {
	if w.Keep <= 0 {
		return
	}
	entries, err := os.ReadDir(w.Dir)
	if err != nil {
		return
	}
	runs := map[string][]string{} // base name -> its files
	for _, e := range entries {
		name := e.Name()
		ext := filepath.Ext(name)
		if e.IsDir() || !slices.Contains([]string{".json", ".log", ".html"}, ext) || name == StateName {
			continue
		}
		base := strings.TrimSuffix(name, ext)
		if !runName.MatchString(base) {
			continue
		}
		runs[base] = append(runs[base], filepath.Join(w.Dir, name))
	}
	bases := make([]string, 0, len(runs))
	for b := range runs {
		bases = append(bases, b)
	}
	// Names start with the UTC time, so they sort oldest first; runs in
	// one second sort by their numeric suffix (-2 before -10).
	slices.SortFunc(bases, compareRuns)
	for _, b := range bases[:max(0, len(bases)-w.Keep)] {
		if slices.ContainsFunc(keep, func(k string) bool { return k != "" && strings.TrimSuffix(filepath.Base(k), ".json") == b }) {
			continue
		}
		for _, f := range runs[b] {
			_ = os.Remove(f)
		}
	}
}

// compareRuns orders two run names by start time, then by suffix.
func compareRuns(a, b string) int {
	at, an := splitRun(a)
	bt, bn := splitRun(b)
	if c := strings.Compare(at, bt); c != 0 {
		return c
	}
	return an - bn
}

// splitRun splits a run name into its time stamp and suffix number; a
// name without a suffix is run 1 of its second.
func splitRun(name string) (stamp string, n int) {
	stamp, suffix, ok := strings.Cut(name, "-")
	if !ok {
		return stamp, 1
	}
	n, _ = strconv.Atoi(suffix)
	return stamp, n
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
