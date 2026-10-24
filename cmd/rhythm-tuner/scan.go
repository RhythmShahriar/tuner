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
	"github.com/RhythmShahriar/rhythm/kit/update"
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
		if errors.As(err, &ue) || strings.HasPrefix(err.Error(), "flag") {
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
		p.targets = append(p.targets, readTargets(f)...)
		_ = f.Close()
	}
	if o.stdin {
		p.targets = append(p.targets, readTargets(stdin)...)
	}
	p.targets = dedupe(p.targets)
	if len(p.targets) == 0 {
		return nil, usagef("scan needs a target\n  try: rhythm tuner scan example.com")
	}
	allLocal := true
	for _, t := range p.targets {
		if isLocalPath(t) {
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
	h := http.Header{}
	for _, raw := range o.headers {
		name, value, ok := strings.Cut(raw, ":")
		if name = strings.TrimSpace(name); !ok || name == "" || strings.ContainsAny(name, " \t") {
			return nil, usagef("bad header %q, use \"Name: value\"", raw)
		}
		h.Add(name, strings.TrimSpace(value))
	}
	if o.cookie != "" {
		h.Add("Cookie", o.cookie)
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
	var out io.Writer
	var file *os.File
	if p.format != "" {
		out = stdout
		if o.output != "" {
			var err error
			if file, err = os.Create(o.output); err != nil {
				fmt.Fprintln(stderr, "rhythm tuner:", err)
				return exitError
			}
			defer func() { _ = file.Close() }() // on early return; checked below otherwise
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

	// Look for a newer release while the scan runs; at most once a day.
	notice := make(chan string, 1)
	go func() {
		u := &update.Updater{Repo: "RhythmShahriar/tuner", Binary: "rhythm-tuner", Current: version,
			UserAgent: p.engine.UserAgent, API: os.Getenv("RHYTHM_GITHUB_API")}
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if latest, newer := u.Check(cctx); newer {
			notice <- fmt.Sprintf("A new release of rhythm-tuner is available: %s → %s\n  run: rhythm update", version, latest)
		}
		close(notice)
	}()

	scanner := engine.New(p.checks, p.engine)
	single := len(p.targets) == 1
	results := make([]*engine.Result, len(p.targets))
	failed := make([]bool, len(p.targets))
	var outMu sync.Mutex
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
					_ = report.JSONLine(out, f)
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
				failed[i] = true
				fmt.Fprintf(stderr, "rhythm tuner: %s: %v\n", target, describe(err))
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
	var werr error
	switch p.format {
	case "json":
		werr = report.JSON(out, reports, len(p.targets) > 1)
	case "sarif":
		werr = report.SARIF(out, reports, version)
	case "md":
		werr = report.Markdown(out, reports)
	}
	if werr == nil && file != nil {
		werr = file.Close()
	}
	if werr != nil {
		fmt.Fprintln(stderr, "rhythm tuner: writing report:", werr)
		return exitError
	}
	if o.output != "" && !o.quiet && len(reports) > 0 {
		fmt.Fprintf(stderr, "Report written to %s\n", o.output)
	}

	if live && !o.quiet {
		select {
		case msg, ok := <-notice:
			if ok {
				fmt.Fprintln(stderr, msg)
			}
		case <-time.After(200 * time.Millisecond): // don't hold up the exit for it
		}
	}

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
	if slices.Contains(failed, true) {
		return exitError
	}
	return exitOK
}

func describe(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "stopped by --max-time; results are partial"
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

// readTargets reads one target per line, skipping blanks and # comments.
func readTargets(r io.Reader) []string {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(f.Fd())
}

func isLocalPath(t string) bool {
	if strings.HasPrefix(t, ".") || strings.HasPrefix(t, "/") || strings.HasPrefix(t, "~") {
		return true
	}
	fi, err := os.Stat(t) //nolint:gosec // only checks whether the user's target is a local directory
	return err == nil && fi.IsDir()
}
