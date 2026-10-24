// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
	"github.com/muesli/termenv"

	"github.com/RhythmShahriar/rhythm/kit/config"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/local"
	"github.com/RhythmShahriar/tuner/report"
	"github.com/RhythmShahriar/tuner/vulns"
)

// listFlag collects comma-separated values across repeated flags.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

// repeatFlag collects each use of a flag verbatim.
type repeatFlag []string

func (r *repeatFlag) String() string     { return strings.Join(*r, "; ") }
func (r *repeatFlag) Set(v string) error { *r = append(*r, v); return nil }

type scanOptions struct {
	json, jsonl, sarif, md         bool
	output                         string
	quiet, plain, noColor, verbose bool

	profile, severity, checksDir       string
	tags, excludeTags, ids, excludeIDs listFlag

	rate             float64
	concurrency      int
	timeout, maxTime time.Duration
	retries          int
	userAgent        string
	headers          repeatFlag
	cookie, proxy    string
	insecure         bool

	offline, noVulns, noCheckUpdates bool
	php                              string // local scans: the php binary to ask for its version

	list     string
	stdin    bool
	parallel int
	failOn   string
	baseline string
}

func scanFlagSet(o *scanOptions, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintln(stderr, "run 'rhythm tuner --help' for all flags") }
	both := func(short, long string, f func(name string)) { f(short); f(long) }

	fs.BoolVar(&o.json, "json", false, "")
	fs.BoolVar(&o.jsonl, "jsonl", false, "")
	fs.BoolVar(&o.sarif, "sarif", false, "")
	fs.BoolVar(&o.md, "md", false, "")
	both("o", "output", func(n string) { fs.StringVar(&o.output, n, "", "") })
	both("q", "quiet", func(n string) { fs.BoolVar(&o.quiet, n, false, "") })
	fs.BoolVar(&o.plain, "plain", false, "")
	fs.BoolVar(&o.noColor, "no-color", false, "")
	both("v", "verbose", func(n string) { fs.BoolVar(&o.verbose, n, false, "") })

	fs.StringVar(&o.profile, "profile", string(engine.ProfileDefault), "")
	fs.Var(&o.tags, "tags", "")
	fs.Var(&o.excludeTags, "exclude-tags", "")
	fs.Var(&o.ids, "id", "")
	fs.Var(&o.excludeIDs, "exclude-id", "")
	fs.StringVar(&o.severity, "severity", "", "")
	fs.StringVar(&o.checksDir, "checks", "", "")

	fs.Float64Var(&o.rate, "rate", 5, "")
	both("c", "concurrency", func(n string) { fs.IntVar(&o.concurrency, n, 10, "") })
	fs.DurationVar(&o.timeout, "timeout", 10*time.Second, "")
	fs.IntVar(&o.retries, "retries", 2, "")
	fs.DurationVar(&o.maxTime, "max-time", 0, "")
	both("A", "user-agent", func(n string) { fs.StringVar(&o.userAgent, n, "", "") })
	both("H", "header", func(n string) { fs.Var(&o.headers, n, "") })
	fs.StringVar(&o.cookie, "cookie", "", "")
	fs.StringVar(&o.proxy, "proxy", "", "")
	both("k", "insecure", func(n string) { fs.BoolVar(&o.insecure, n, false, "") })

	fs.BoolVar(&o.offline, "offline", false, "")
	fs.BoolVar(&o.noVulns, "no-vulns", false, "")
	fs.BoolVar(&o.noCheckUpdates, "no-check-updates", false, "")
	fs.StringVar(&o.php, "php", "", "")

	both("l", "list", func(n string) { fs.StringVar(&o.list, n, "", "") })
	fs.BoolVar(&o.stdin, "stdin", false, "")
	fs.IntVar(&o.parallel, "parallel", 4, "")
	fs.StringVar(&o.failOn, "fail-on", "", "")
	fs.StringVar(&o.baseline, "baseline", "", "")
	return fs
}

// parseInterspersed lets flags come before or after positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

// scanPlan is everything scan needs once flags are validated.
type scanPlan struct {
	o        scanOptions
	targets  []string
	checks   []*engine.Check
	checkSet *checkSet
	engine   engine.Options
	sel      engine.Selector
	osv      *local.OSV
	format   string // json, jsonl, sarif, md, or "" for the terminal view only
	failOn   engine.Severity
	baseline report.Baseline

	// local is the base for local scans; scanTarget copies it and fills in
	// PHP, Advisor, OSV and Select.
	local local.Options
	// write is passed to the report writer.
	write writeOptions
}

func scan(args []string, stdout, stderr io.Writer) int {
	plan, err := planScan(args, os.Stdin)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(stdout)
			return exitOK
		}
		fmt.Fprintln(stderr, "rhythm tuner:", err)
		var ue usageError
		if errors.As(err, &ue) {
			return exitUsage
		}
		return exitError
	}
	return execute(plan, stdout, stderr)
}

func planScan(args []string, stdin io.Reader) (*scanPlan, error) {
	p := &scanPlan{}
	o := &p.o
	flags := scanFlagSet(o, io.Discard)
	for _, e := range scanExtensions {
		e.Flags(flags)
	}
	pos, err := parseInterspersed(flags, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, usageError{err.Error()}
	}

	// Targets.
	p.targets = pos
	if o.list != "" {
		f, err := os.Open(o.list)
		if err != nil {
			return nil, err
		}
		more, err := readTargets(f, o.list)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		p.targets = append(p.targets, more...)
	}
	if o.stdin {
		more, err := readTargets(stdin, "stdin")
		if err != nil {
			return nil, err
		}
		p.targets = append(p.targets, more...)
	}
	p.targets = dedupe(p.targets)
	if len(p.targets) == 0 {
		return nil, usagef("scan needs a target\n  try: rhythm tuner scan example.com")
	}
	allLocal := true
	for _, t := range p.targets {
		isLocal, err := classifyTarget(t)
		if err != nil {
			return nil, err
		}
		if isLocal {
			if _, err := local.Root(t); err != nil {
				return nil, usageError{err.Error()}
			}
			continue
		}
		allLocal = false
		if _, _, err := engine.ParseTarget(t); err != nil {
			return nil, usageError{err.Error()}
		}
	}

	// Output format.
	var chosen []string
	for name, on := range map[string]bool{"json": o.json, "jsonl": o.jsonl, "sarif": o.sarif, "md": o.md} {
		if on {
			chosen = append(chosen, name)
		}
	}
	switch {
	case len(chosen) > 1:
		slices.Sort(chosen)
		return nil, usagef("pick one output format, not --%s", strings.Join(chosen, " and --"))
	case len(chosen) == 1:
		p.format = chosen[0]
	case o.output != "":
		if p.format = formatFromExt(o.output); p.format == "" {
			return nil, usagef("can't tell the format of %s; add --json, --jsonl, --sarif or --md", o.output)
		}
	}

	// Proxy first: check pack downloads go through it too.
	var proxy *url.URL
	if o.proxy != "" {
		u, err := url.Parse(o.proxy)
		if err != nil || u.Host == "" || !slices.Contains([]string{"http", "https", "socks5", "socks5h"}, u.Scheme) {
			return nil, usagef("bad --proxy %q, use e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:1080", o.proxy)
		}
		proxy = u
	}
	ua := o.userAgent
	if ua == "" {
		ua = fmt.Sprintf("rhythm-tuner/%s (+https://rythm.sh/tuner)", version)
	}

	// Checks.
	// Local scans don't run HTTP checks, so they never need a check pack.
	p.checkSet, err = loadCheckSet(o.checksDir, !o.noCheckUpdates && !allLocal, o.offline, ua, proxy)
	if err != nil {
		return nil, fmt.Errorf("loading checks: %w", err)
	}
	all := p.checkSet.checks
	sel := engine.Selector{
		Profile:     engine.Profile(o.profile),
		Tags:        o.tags,
		ExcludeTags: o.excludeTags,
		IDs:         o.ids,
		ExcludeIDs:  o.excludeIDs,
		MinSeverity: engine.Severity(o.severity),
	}
	vulnsOn := !o.noVulns && wantsVulns(sel)
	p.checks, err = engine.Select(all, sel)
	if err != nil && (!errors.Is(err, engine.ErrNoChecks) || !vulnsOn && !allLocal) {
		return nil, usageError{err.Error()}
	}

	// CI.
	if o.failOn != "" {
		if p.failOn = engine.Severity(o.failOn); p.failOn.Rank() < 0 {
			return nil, usagef("--fail-on %q: want one of %v", o.failOn, engine.Severities)
		}
	}
	if o.baseline != "" {
		if p.baseline, err = report.LoadBaseline(o.baseline); err != nil {
			return nil, err
		}
	}

	// Requests.
	if o.rate < 0 || o.concurrency < 1 || o.retries < 0 || o.parallel < 1 || o.timeout <= 0 {
		return nil, usagef("--rate, --retries must be >= 0; --concurrency, --parallel and --timeout must be positive")
	}
	// Go's HTTP client would refuse a line break in a header on every
	// request, which reads as an unreachable site; catch it here instead.
	h := http.Header{}
	for _, raw := range o.headers {
		name, value, ok := strings.Cut(raw, ":")
		value = strings.TrimSpace(value)
		if name = strings.TrimSpace(name); !ok || !validHeaderName(name) {
			return nil, usagef("bad header %q, use \"Name: value\"", raw)
		}
		if !validHeaderValue(value) {
			return nil, usagef("bad header %q: the value can't hold line breaks or control characters", raw)
		}
		h.Add(name, value)
	}
	if !validHeaderValue(o.cookie) {
		return nil, usagef("bad --cookie: it can't hold line breaks or control characters")
	}
	if o.cookie != "" {
		h.Add("Cookie", o.cookie)
	}
	if !validHeaderValue(ua) {
		return nil, usagef("bad --user-agent: it can't hold line breaks or control characters")
	}
	p.engine = engine.Options{
		UserAgent:   ua,
		Headers:     h,
		Rate:        o.rate,
		Timeout:     o.timeout,
		Concurrency: o.concurrency,
		Retries:     o.retries,
		Insecure:    o.insecure,
		Profile:     engine.Profile(o.profile),
		Proxy:       proxy,
	}
	if vulnsOn {
		p.engine.Advisor = engine.Filtered(&vulns.Advisor{Client: vulnClient(ua, p.engine.Proxy, o.offline)}, sel)
	}
	p.sel = sel
	if vulnsOn {
		p.osv = osvClient(ua, p.engine.Proxy, o.offline)
	}
	p.write = writeOptions{Many: len(p.targets) > 1, Version: version}

	for _, e := range scanExtensions {
		if err := e.Plan(p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func execute(p *scanPlan, stdout, stderr io.Writer) int {
	o := p.o
	tty := isTerminal(stdout)
	plain := o.plain || !tty
	if plain || o.noColor {
		lipgloss.SetColorProfile(termenv.Ascii)
	}

	// Machine output goes to the -o file, else stdout (replacing the live view).
	// The file is created now, before any request, so an unwritable folder
	// fails fast instead of after a long scan.
	var out io.Writer
	var file *reportFile
	if p.format != "" {
		out = stdout
		if o.output != "" {
			var err error
			if file, err = createReport(o.output); err != nil {
				fmt.Fprintln(stderr, "rhythm tuner:", err)
				return exitError
			}
			defer file.discard() // on early return; does nothing after commit
			out = file
		}
	}
	live := p.format == "" || o.output != ""

	if !o.quiet {
		for _, w := range p.checkSet.warnings {
			fmt.Fprintln(stderr, "rhythm tuner:", w)
		}
	}

	if config.FirstRun("tuner-authorised-use") {
		fmt.Fprint(stderr, "Note: scan only sites you own or are authorised to test.\n"+
			"Tuner is non-intrusive and never sends exploit payloads. This notice is shown once.\n\n")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if o.maxTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.maxTime)
		defer cancel()
	}

	notice := checkForUpdate(ctx, p.engine.UserAgent, o.offline)

	scanner := engine.New(p.checks, p.engine)
	single := len(p.targets) == 1
	results := make([]*engine.Result, len(p.targets))
	failed := make([]string, len(p.targets)) // why each target failed, or ""
	var outMu sync.Mutex
	var jsonlErr error // the first failed --jsonl write, guarded by outMu
	var wg sync.WaitGroup
	sem := make(chan struct{}, p.o.parallel)

	for i, target := range p.targets {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()

			// With several targets, buffer each one's view and print it whole.
			var buf bytes.Buffer
			w := stdout
			if !single {
				w = &buf
			}
			var view *report.Pretty
			if live {
				view = report.NewPretty(w, stderr, report.PrettyOptions{
					Plain: plain, Quiet: o.quiet, Progress: single && tty && !o.verbose,
				})
				view.Header(version, target)
			}

			var h engine.Hooks
			if view != nil {
				h.Fingerprint, h.Baseline, h.Progress = view.Fingerprint, view.Baseline, view.Progress
			}
			h.Finding = func(f engine.Finding) {
				if p.baseline.Has(f) {
					return
				}
				if view != nil {
					view.Finding(f)
				}
				if p.format == "jsonl" {
					outMu.Lock()
					if err := report.JSONLine(out, f); err != nil && jsonlErr == nil {
						jsonlErr = err // a full disk or closed pipe; reported once at the end
					}
					outMu.Unlock()
				}
			}
			if o.verbose {
				if view == nil {
					view = report.NewPretty(io.Discard, stderr, report.PrettyOptions{Plain: plain})
				}
				h.Request = view.Request
			}

			res, err := p.scanTarget(ctx, scanner, target, h)
			if res != nil {
				stampFindings(res, target)
				suppressed := p.baseline.Filter(res)
				if live {
					view.Summary(res, target, suppressed)
				}
				results[i] = res
			}
			outMu.Lock()
			defer outMu.Unlock()
			if !single {
				_, _ = stdout.Write(buf.Bytes())
			}
			if err != nil && !errors.Is(err, context.Canceled) {
				failed[i] = describe(ctx, err, o)
				fmt.Fprintf(stderr, "rhythm tuner: %s: %v\n", target, failed[i])
			}
		})
	}
	wg.Wait()

	var reports []report.Report
	for _, res := range results {
		if res != nil {
			r := report.New(res, version)
			r.CheckSet = p.checkSet.source
			if p.checkSet.pack != nil {
				r.CheckPack = p.checkSet.pack.Version
			}
			reports = append(reports, r)
		}
	}
	for i, why := range failed {
		if why != "" {
			p.write.Failed = append(p.write.Failed, targetError{Target: p.targets[i], Error: why})
		}
	}
	// A file keeps its previous report unless this run has a better one.
	keep := ""
	switch {
	case file == nil:
	case errors.Is(ctx.Err(), context.Canceled):
		keep = "scan canceled"
	case len(reports) == 0 && len(p.write.Failed) > 0:
		keep = "every target failed"
	}
	werr := jsonlErr
	if werr != nil && file != nil {
		keep = "the report could not be written in full"
	}
	if keep == "" && p.format != "" && p.format != "jsonl" {
		werr = writeReport(p.format, out, reports, p.write)
	}
	switch {
	case keep != "":
		file.discard()
		fmt.Fprintln(stderr, "rhythm tuner: no report written:", keep)
	case werr == nil && file != nil:
		werr = file.commit()
	}
	if werr != nil {
		fmt.Fprintln(stderr, "rhythm tuner: writing report:", werr)
		return exitError
	}
	if keep == "" && o.output != "" && !o.quiet && len(reports) > 0 {
		fmt.Fprintf(stderr, "Report written to %s\n", o.output)
	}

	if live && !o.quiet {
		printUpdateNotice(notice, stderr)
	}

	exit := scanExit(ctx, p, reports, failed, stderr)
	for _, e := range scanExtensions {
		code, err := e.Finished(p, reports, stderr)
		if err != nil {
			fmt.Fprintln(stderr, "rhythm tuner:", err)
			code = max(code, exitError)
		}
		exit = max(exit, code)
	}
	return exit
}

// scanExit picks the built-in exit code once every target is done.
func scanExit(ctx context.Context, p *scanPlan, reports []report.Report, failed []string, stderr io.Writer) int {
	if errors.Is(ctx.Err(), context.Canceled) {
		fmt.Fprintln(stderr, "rhythm tuner: scan canceled; results are partial")
		return exitCanceled
	}
	if p.failOn != "" {
		for _, r := range reports {
			if w := r.Worst(); w != "" && w.Rank() <= p.failOn.Rank() {
				return exitFindings
			}
		}
	}
	if slices.ContainsFunc(failed, func(why string) bool { return why != "" }) {
		return exitError
	}
	return exitOK
}

// reportFile is a report being written next to its destination. It
// replaces the destination only once complete, so a killed, canceled or
// failed run never leaves the previous report truncated, and two cron
// runs writing the same path never interleave.
type reportFile struct {
	*os.File
	dest string
	done bool
}

func createReport(dest string) (*reportFile, error) {
	if fi, err := os.Stat(dest); err == nil && fi.IsDir() {
		return nil, fmt.Errorf("can't write the report to %s: it is a directory", dest)
	}
	dir := filepath.Dir(dest)
	f, err := os.CreateTemp(dir, "."+filepath.Base(dest)+".*.tmp")
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err // the temporary name means nothing to the user
		}
		return nil, fmt.Errorf("can't write the report to %s: %w", dir, err)
	}
	return &reportFile{File: f, dest: dest}, nil
}

// commit flushes the report to disk and moves it into place. A report
// that replaces another keeps its permissions; a new one gets 0644, as
// os.Create gives under the usual umask.
func (r *reportFile) commit() error {
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(r.dest); err == nil {
		mode = fi.Mode().Perm()
	}
	err := r.Chmod(mode)
	if err == nil {
		err = r.Sync()
	}
	if cerr := r.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(r.Name(), r.dest)
	}
	if err != nil {
		_ = os.Remove(r.Name())
	}
	r.done = true
	return err
}

// discard drops an unfinished report and leaves the destination alone.
func (r *reportFile) discard() {
	if !r.done {
		r.done = true
		_ = r.Close()
		_ = os.Remove(r.Name())
	}
}

// targetError and writeOptions mirror report.TargetError and
// report.WriteOptions from the report writer registry. Until that registry
// is released, writeReport dispatches to the existing writers; then all
// three become report.TargetError, report.WriteOptions and report.Write.
type targetError struct{ Target, Error string }

type writeOptions struct {
	Many    bool          // several targets: JSON is an array
	Failed  []targetError // targets that could not be scanned
	Version string        // the rhythm-tuner version
}

func writeReport(format string, w io.Writer, reports []report.Report, o writeOptions) error {
	switch format {
	case "json":
		return report.JSON(w, reports, o.Many)
	case "sarif":
		return report.SARIF(w, reports, o.Version)
	case "md":
		return report.Markdown(w, reports)
	}
	return fmt.Errorf("no writer for %s reports", format)
}

// stampFindings gives each finding a stable fingerprint before baseline
// filtering. It is a seam for report.Stamp, which does nothing yet either.
func stampFindings(*engine.Result, string) {}

// describe explains why a target failed. The run context tells a --max-time
// stop apart from one slow request, which wraps the same DeadlineExceeded.
func describe(ctx context.Context, err error, o scanOptions) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded) && errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "stopped by --max-time; results are partial"
	case isTimeout(err):
		tries := "once"
		if o.retries > 0 {
			tries = fmt.Sprintf("%d times", o.retries+1)
		}
		return fmt.Sprintf("no response within %s (tried %s)\n  raise --timeout if the site is just slow", o.timeout, tries)
	case strings.HasPrefix(err.Error(), "can't reach"):
		return err.Error() + "\n  check the address and that the site is up"
	}
	return err.Error()
}

func formatFromExt(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "json"
	case ".jsonl", ".ndjson":
		return "jsonl"
	case ".sarif":
		return "sarif"
	case ".md", ".markdown":
		return "md"
	}
	return ""
}

// wantsVulns reports whether a selection includes vulnerability matching:
// always, unless tags or IDs were given that leave it out.
func wantsVulns(s engine.Selector) bool {
	if slices.Contains(s.ExcludeTags, "vuln") {
		return false
	}
	advisorTags := []string{"vuln", "wordpress", "php", "outdated", "abandoned", "nginx", "apache", "core", "plugin", "theme", "composer", "known-exploited"}
	if len(s.Tags) > 0 && !hasAny(s.Tags, advisorTags) {
		return false
	}
	return len(s.IDs) == 0 || slices.ContainsFunc(s.IDs, engine.IsAdvisorID)
}

func hasAny(have, want []string) bool {
	return slices.ContainsFunc(want, func(t string) bool { return slices.Contains(have, t) })
}

// vulnClient builds the vulnerability data client. It goes through the
// same proxy as the scan.
func vulnClient(ua string, proxy *url.URL, offline bool) *vulns.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	}
	return &vulns.Client{
		HTTP:      &http.Client{Transport: tr, Timeout: 20 * time.Second},
		UserAgent: ua,
		CacheDir:  vulns.DefaultCacheDir(),
		Offline:   offline,
		VulnBase:  os.Getenv("TUNER_VULN_API"),  // a mirror; default wpvulnerability.net
		WPOrgBase: os.Getenv("TUNER_WPORG_API"), // default api.wordpress.org

		// PHP's supported branches, for hidden and end-of-life PHP versions.
		PHPNetBase: os.Getenv("TUNER_PHPNET_API"), // default www.php.net
	}
}

// isTimeout reports whether a single request ran out of time. The engine
// will mark these with its own error; until then, the net package's
// Timeout flag says the same.
func isTimeout(err error) bool {
	var ne interface{ Timeout() bool }
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
}

// maxTargetLen bounds one target. No URL or path to a site is this long,
// so a longer line is a pasted file or a broken export, not a site.
const maxTargetLen = 4096

// readTargets reads one target per line, skipping blanks and # comments.
// It accepts files saved on Windows (a byte order mark, CRLF endings).
// name says where the lines came from, for errors.
func readTargets(r io.Reader, name string) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		text := sc.Text()
		if n == 1 {
			text = strings.TrimPrefix(text, "\uFEFF")
		}
		line, _, _ := strings.Cut(text, "#")
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		if len(line) > maxTargetLen {
			return nil, usagef("%s line %d: %d characters is too long for a target", name, n, len(line))
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, usagef("%s line %d: longer than 1 MiB; is this a list of sites?", name, n+1)
		}
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}
	return out, nil
}

// dedupe drops targets that name the same site or folder, keeping the
// first spelling: example.com, https://example.com/ and HTTPS://Example.com
// are one scan.
func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if k := targetKey(s); !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

// targetKey is the form two spellings of one target share. A bare host is
// scanned over https first, so it matches https://host.
func targetKey(t string) string {
	if isLocal, err := classifyTarget(t); err != nil {
		return t // planScan reports it
	} else if isLocal {
		if root, err := local.Root(t); err == nil {
			return "file:" + root
		}
		return t
	}
	u, _, err := engine.ParseTarget(t)
	if err != nil {
		return t
	}
	host := strings.ToLower(u.Hostname())
	defaultPort := map[string]string{"http": "80", "https": "443"}[u.Scheme]
	if port := u.Port(); port != "" && port != defaultPort {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return u.Scheme + "://" + host + strings.TrimRight(u.EscapedPath(), "/") + "?" + u.RawQuery
}

// validHeaderName reports whether s is an HTTP token (RFC 9110 5.1).
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		alnum := c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !alnum && strings.IndexByte("!#$%&'*+-.^_`|~", c) < 0 {
			return false
		}
	}
	return true
}

// validHeaderValue reports whether s can go in a header: no control
// characters but tab (RFC 9110 5.5), so no CR or LF to split the request.
func validHeaderValue(s string) bool {
	for _, c := range []byte(s) {
		if c < 0x20 && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(f.Fd())
}

// isLocalPath reports whether t names a folder to scan in place. Only
// path-shaped targets are local, so a folder that happens to share a
// site's name never turns a remote scan into a local one.
func isLocalPath(t string) bool {
	local, _ := classifyTarget(t)
	return local
}

// classifyTarget reports whether t is a local folder. A target that could
// be read either way is a usage error, because guessing wrong either skips
// the site or sends requests to a host the user never meant to scan.
func classifyTarget(t string) (local bool, err error) {
	if strings.Contains(t, "://") {
		return false, nil
	}
	if t == "." || t == ".." || t == "~" || hasAnyPrefix(t, "./", "../", ".\\", "..\\", "/", "\\", "~/", "~\\") || isDrivePath(t) {
		return true, nil
	}
	first, _, hasSep := strings.Cut(strings.ReplaceAll(t, "\\", "/"), "/")
	if hasSep && !looksLikeHost(first) {
		return true, nil // sites/example: a relative path
	}
	// A bare name, or host/path such as example.com/blog.
	if isDir(t) {
		return false, usagef("%s is both a folder here and a hostname; use ./%s or https://%s", t, t, t)
	}
	return false, nil
}

// looksLikeHost reports whether the first path segment reads as a host
// (example.com, localhost, 127.0.0.1:8080) rather than a folder name.
func looksLikeHost(s string) bool {
	return s == "localhost" || strings.ContainsAny(s, ".:")
}

func isDrivePath(t string) bool {
	return len(t) >= 2 && t[1] == ':' && (t[0]|0x20 >= 'a' && t[0]|0x20 <= 'z') &&
		(len(t) == 2 || t[2] == '/' || t[2] == '\\')
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(s, p) })
}

func isDir(t string) bool {
	fi, err := os.Stat(t) //nolint:gosec // only checks whether the user's target is a local directory
	return err == nil && fi.IsDir()
}
