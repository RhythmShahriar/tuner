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
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/config"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/local"
	"github.com/RhythmShahriar/tuner/report"
	// The package is run; main already has a func run.
	scanrun "github.com/RhythmShahriar/tuner/run"
	"github.com/RhythmShahriar/tuner/tunerconfig"
	"github.com/RhythmShahriar/tuner/vulns"
)

// Short names for the kit's flag and error helpers, which every command
// in this package shares.
type (
	listFlag   = cli.ListFlag   // comma-separated values across repeated flags
	usageError = cli.UsageError // a bad command line: exit 2
)

// usagef builds a usageError.
var usagef = cli.Usagef

type scanOptions struct {
	json, jsonl, sarif, md         bool
	jsonArray                      bool // JSON, always an array
	output                         string
	quiet, plain, noColor, verbose bool

	profile, severity, checksDir       string
	tags, excludeTags, ids, excludeIDs listFlag

	rate             float64
	concurrency      int
	timeout, maxTime time.Duration
	retries          int
	userAgent        string
	headers          cli.RepeatFlag
	cookie, proxy    string
	insecure         bool

	offline, noVulns, noCheckUpdates bool
	php                              string // local scans: the php binary to ask for its version

	list     string
	stdin    bool
	parallel int
	failOn   string
	baseline string
	// minConfidence is confirmed or likely: the least confidence a
	// finding needs to count for --fail-on.
	minConfidence string

	// allowMissingVulns and allowPartial let --fail-on pass a run it
	// would otherwise not trust; see scanExit.
	allowMissingVulns, allowPartial bool

	config   string // --config: the settings file to read instead of .tuner.yml
	noConfig bool   // --no-config: read no settings file
}

func scanFlagSet(o *scanOptions, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintf(stderr, "run '%s scan --help' for all flags\n", cmdName()) }
	both := func(short, long string, f func(name string)) { f(short); f(long) }

	fs.BoolVar(&o.json, "json", false, "")
	fs.BoolVar(&o.jsonArray, "json-array", false, "")
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

	fs.Float64Var(&o.rate, "rate", defaultRate, "")
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
	fs.StringVar(&o.minConfidence, "min-confidence", confidenceLikely, "")
	fs.StringVar(&o.baseline, "baseline", "", "")
	fs.BoolVar(&o.allowMissingVulns, "allow-missing-vulns", false, "")
	fs.BoolVar(&o.allowPartial, "allow-partial", false, "")
	fs.StringVar(&o.config, "config", "", "")
	fs.BoolVar(&o.noConfig, "no-config", false, "")
	return fs
}

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
	// confirmedOnly makes --fail-on count only confirmed findings
	// (--min-confidence confirmed). Likely ones are still reported.
	confirmedOnly bool

	// config is the settings file in use, or nil. Its ignore entries are
	// split into ignores, which hide findings like a baseline, and
	// expired, which hide nothing and get a note on stderr.
	config           *tunerconfig.Config
	configTargets    []string
	configBaseline   bool // the baseline was named in the config, not by --baseline
	ignores, expired []tunerconfig.Ignore

	// fast holds the targets on the user's own machine or network. Without
	// --rate (or rate in the config) they are scanned at localRate.
	fast map[string]bool
	// notes go to stderr before the scan, unless -q.
	notes []string

	// local is the base for local scans; scanTarget copies it and fills in
	// PHP, Advisor, OSV and Select.
	local local.Options
	// localFor lets extensions adjust one local target's options, such as
	// the nested installs --discover scans on their own.
	localFor []func(target string, o *local.Options)
	// write is passed to the report writer.
	write report.WriteOptions
}

func scan(args []string, stdout, stderr io.Writer) int {
	plan, err := planScan(args, os.Stdin)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			scanUsage(stdout)
			return exitOK
		}
		printErr(stderr, "scan", err)
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
	pos, err := cli.ParseInterspersed(flags, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, flagError(flags, err)
	}
	set := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if err := p.applyConfig(set, len(pos) > 0 || o.list != "" || o.stdin); err != nil {
		return nil, err
	}
	if err := p.checkValues(); err != nil {
		return nil, err
	}

	// Targets.
	p.targets = append(pos, p.configTargets...)
	if o.list != "" {
		f, err := os.Open(o.list)
		if err != nil {
			return nil, usagef("-l %s: %v", o.list, unwrapPath(err))
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
		return nil, usagef("no target given\n  try: %s scan example.com", cmdName())
	}
	allLocal := true
	for _, t := range p.targets {
		isLocal, err := classifyTarget(t)
		if err != nil {
			return nil, err
		}
		if isLocal {
			if _, err := local.Root(t); err != nil {
				return nil, usageError{Msg: err.Error()}
			}
			continue
		}
		allLocal = false
		if _, _, err := engine.ParseTarget(t); err != nil {
			return nil, usageError{Msg: err.Error()}
		}
	}

	// Output format.
	var chosen []string
	for name, on := range map[string]bool{"json": o.json || o.jsonArray, "jsonl": o.jsonl, "sarif": o.sarif, "md": o.md} {
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
		if p.format = report.FormatForExt(o.output); p.format == "" {
			return nil, usagef("can't tell the format of %s; add --json, --jsonl, --sarif or --md, or end the name in .html", o.output)
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
	if err := checkIDs(all, o.ids, o.excludeIDs); err != nil {
		return nil, err
	}
	p.checks, err = engine.Select(all, sel)
	if err != nil && (!errors.Is(err, engine.ErrNoChecks) || !vulnsOn && !allLocal) {
		return nil, usageError{Msg: err.Error()}
	}

	// CI.
	if o.baseline != "" {
		if p.baseline, err = report.LoadBaseline(o.baseline); err != nil {
			return nil, err
		}
	}

	// Requests.
	// Go's HTTP client would refuse a line break in a header on every
	// request, which reads as an unreachable site; catch it here instead.
	h := http.Header{}
	for _, raw := range o.headers {
		name, value, ok := strings.Cut(raw, ":")
		value = strings.TrimSpace(value)
		if name = strings.TrimSpace(name); !ok || !validHeaderName(name) {
			// The name alone may be the start of a credential, so this
			// message shows nothing of what was given.
			return nil, usagef("bad -H: use \"Name: value\"")
		}
		if !validHeaderValue(value) {
			// Name the header, never quote its value: it is often a token.
			return nil, usagef("bad -H %s: the value can't hold line breaks or control characters", name)
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
		// The tracker sits inside the filter so it sees every lookup,
		// including ones whose findings the selection drops.
		p.engine.Advisor = engine.Filtered(scanrun.TrackVulns(&vulns.Advisor{Client: vulnClient(ua, p.engine.Proxy, o.offline)}), sel)
	}
	p.sel = sel
	if vulnsOn {
		p.osv = osvClient(ua, p.engine.Proxy, o.offline)
	}
	p.write = report.WriteOptions{Many: len(p.targets) > 1, Array: o.jsonArray, Version: version}

	for _, e := range scanExtensions {
		if err := e.Plan(p); err != nil {
			return nil, err
		}
	}
	if !set["rate"] && (p.config == nil || p.config.Rate == nil) {
		p.fast = ownNetworkTargets(p.targets, proxy != nil)
	}
	if o.profile == string(engine.ProfileDeep) && !slices.ContainsFunc(all, func(c *engine.Check) bool { return c.Profile == engine.ProfileDeep }) {
		p.notes = append(p.notes, "--profile deep: no check uses it yet, so it runs the same checks as default")
	}
	return p, nil
}

// Request rates when --rate is not given. A site on the internet gets a
// polite default. One on loopback or a private network is almost always
// the user's own dev or staging server, where the rate limit would be
// the whole cost of the scan (78 requests take 15 s at 5/s, 1 s at 50/s).
const (
	defaultRate = 5
	localRate   = 50
)

// maxLookups is how many DNS lookups ownNetworkTargets runs at once.
const maxLookups = 16

// lookupIP resolves a host for ownNetworkTargets. Tests replace it so
// they never send a DNS query.
var lookupIP = net.DefaultResolver.LookupIPAddr

// ownNetworkTargets returns the URL targets whose host is loopback,
// private or link-local: a literal address, localhost, or a name that
// resolves only to such addresses. Names are resolved in parallel with
// a short timeout; a name that fails to resolve counts as public. Behind
// a proxy (--proxy or HTTPS_PROXY) the scan's DNS happens elsewhere, so
// only literal addresses and localhost count.
func ownNetworkTargets(targets []string, proxied bool) map[string]bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fast := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	// A list of thousands of sites would otherwise send thousands of
	// lookups at once, which resolvers drop: those sites would quietly
	// get the public rate.
	sem := make(chan struct{}, maxLookups)
	for _, t := range targets {
		if isLocalPath(t) {
			continue
		}
		u, _, err := engine.ParseTarget(t)
		if err != nil {
			continue
		}
		viaProxy := proxied
		if pu, err := http.ProxyFromEnvironment(&http.Request{URL: u}); err == nil && pu != nil {
			viaProxy = true
		}
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			if ownNetworkHost(ctx, host, viaProxy) {
				mu.Lock()
				fast[t] = true
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return fast
}

// ownNetworkHost reports whether host is on the user's own machine or
// network. See ownNetworkTargets.
func ownNetworkHost(ctx context.Context, host string, proxied bool) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true // RFC 6761: always loopback
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ownNetworkIP(ip)
	}
	if proxied {
		return false
	}
	addrs, err := lookupIP(ctx, host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok || !ownNetworkIP(ip) {
			return false
		}
	}
	return true
}

// ownNetworkIP reports whether ip is loopback, private (RFC 1918 or an
// IPv6 unique local address) or link-local.
func ownNetworkIP(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// rateFor is the request rate one target is scanned at.
func (p *scanPlan) rateFor(target string) float64 {
	if p.fast[target] {
		return localRate
	}
	return p.engine.Rate
}

// today is the date ignore entries are checked against. Tests change it.
var today = time.Now

// applyConfig reads .tuner.yml (or the --config file) and fills in every
// option the command line left unset: flags always win. Its targets are
// used only when none were given in any other way.
func (p *scanPlan) applyConfig(set map[string]bool, haveTargets bool) error {
	o := &p.o
	if o.noConfig && o.config != "" {
		return usagef("--config and --no-config don't go together")
	}
	if o.noConfig {
		return nil
	}
	path := o.config
	if path == "" {
		found, err := tunerconfig.Find(".")
		if err != nil || found == "" {
			return err
		}
		path = found
	} else if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return usagef("--config %s: no such file", path)
	} else if err != nil {
		return usagef("--config %s: %v", path, unwrapPath(err))
	}
	c, err := tunerconfig.Load(path)
	if err != nil {
		return usageError{Msg: err.Error()}
	}
	p.config = c

	str := func(flagName string, dst *string, v string) {
		if !set[flagName] && v != "" {
			*dst = v
		}
	}
	list := func(flagName string, dst *listFlag, v []string) {
		if !set[flagName] && len(v) > 0 {
			*dst = v
		}
	}
	str("profile", &o.profile, c.Profile)
	str("fail-on", &o.failOn, c.FailOn)
	str("min-confidence", &o.minConfidence, c.MinConfidence)
	str("baseline", &o.baseline, c.Baseline)
	p.configBaseline = !set["baseline"] && c.Baseline != ""
	list("tags", &o.tags, c.Tags)
	list("exclude-tags", &o.excludeTags, c.ExcludeTags)
	list("id", &o.ids, c.IDs)
	list("exclude-id", &o.excludeIDs, c.ExcludeIDs)
	if c.Rate != nil && !set["rate"] {
		o.rate = *c.Rate
	}
	if c.Concurrency != nil && !set["c"] && !set["concurrency"] {
		o.concurrency = *c.Concurrency
	}
	// A header given with -H replaces the config's header of that name.
	var headers cli.RepeatFlag
	for _, h := range c.Headers {
		name, _, _ := strings.Cut(h, ":")
		if !slices.ContainsFunc(o.headers, func(f string) bool {
			given, _, _ := strings.Cut(f, ":")
			return strings.EqualFold(strings.TrimSpace(given), name)
		}) {
			headers = append(headers, h)
		}
	}
	o.headers = append(headers, o.headers...)

	if !haveTargets {
		dir := filepath.Dir(c.Path)
		for _, t := range c.Targets {
			// A folder in the config is relative to the config's folder.
			if isLocal, err := classifyTarget(t); err == nil && isLocal && dir != "." && !filepath.IsAbs(t) && !strings.HasPrefix(t, "~") {
				t = filepath.Join(dir, t)
				if !filepath.IsAbs(t) {
					t = "." + string(filepath.Separator) + t
				}
			}
			p.configTargets = append(p.configTargets, t)
		}
		// A .tuner.yml can come with a pull request, which could point
		// targets at a host it controls. Credentials from the command line
		// (often CI secrets) must never go to a host only the file chose.
		if len(p.configTargets) > 0 && (set["H"] || set["header"] || set["cookie"]) {
			return usagef("-H and --cookie need targets on the command line when %s chooses them: name the targets or use --no-config", c.Path)
		}
	}
	p.ignores, p.expired = c.Ignores(today())
	return nil
}

// checkValues validates and normalises the flags that take one of a few
// values or a number, before anything slow runs. Names of levels and
// profiles are accepted in any case.
func (p *scanPlan) checkValues() error {
	o := &p.o
	// deep is still accepted. No check uses it yet, so help and errors
	// leave it out.
	profile := engine.ProfileDeep
	if !strings.EqualFold(strings.TrimSpace(o.profile), string(engine.ProfileDeep)) {
		var err error
		if profile, err = oneOf("profile", o.profile, []engine.Profile{engine.ProfileQuick, engine.ProfileDefault}); err != nil {
			return err
		}
	}
	o.profile = string(profile)
	if o.severity != "" {
		sev, err := oneOf("severity", o.severity, engine.Severities)
		if err != nil {
			return err
		}
		o.severity = string(sev)
	}
	var err error
	if o.failOn != "" {
		if p.failOn, err = oneOf("fail-on", o.failOn, engine.Severities); err != nil {
			return err
		}
	}
	confidence, err := oneOf("min-confidence", o.minConfidence, []string{confidenceConfirmed, confidenceLikely})
	if err != nil {
		return err
	}
	o.minConfidence = confidence
	p.confirmedOnly = confidence == confidenceConfirmed

	for _, c := range []struct {
		flag string
		bad  bool
		want string
	}{
		{"rate", o.rate < 0, "0 or more (0 means no limit)"},
		{"concurrency", o.concurrency < 1, "1 or more"},
		{"retries", o.retries < 0, "0 or more"},
		{"parallel", o.parallel < 1, "1 or more"},
	} {
		if c.bad {
			return usagef("--%s %s: want %s", c.flag, flagValue(c.flag, o), c.want)
		}
	}
	if o.timeout <= 0 {
		return usagef("--timeout %s: want a positive duration, for example 10s", o.timeout)
	}
	if o.maxTime < 0 {
		return usagef("--max-time %s: want a positive duration, for example 10m", o.maxTime)
	}
	return nil
}

// flagValue prints a numeric option the way it was typed.
func flagValue(name string, o *scanOptions) string {
	switch name {
	case "rate":
		return strconv.FormatFloat(o.rate, 'g', -1, 64)
	case "concurrency":
		return strconv.Itoa(o.concurrency)
	case "retries":
		return strconv.Itoa(o.retries)
	}
	return strconv.Itoa(o.parallel)
}

// checkIDs catches a check ID that matches nothing (such as a typo in
// --id leak-dotnev) and suggests the closest one. Patterns with globs and
// IDs the advisors and local scans produce are left to engine.Select.
func checkIDs(all []*engine.Check, ids, excluded []string) error {
	known := make([]string, len(all))
	for i, c := range all {
		known[i] = c.ID
	}
	for _, list := range []struct {
		flag string
		ids  []string
	}{{"id", ids}, {"exclude-id", excluded}} {
		for _, id := range list.ids {
			if strings.ContainsAny(id, "*?[") || engine.IsAdvisorID(id) || slices.Contains(known, id) {
				continue
			}
			msg := fmt.Sprintf("--%s %s: no check has this ID", list.flag, id)
			if s := suggest(id, known); s != "" {
				msg += fmt.Sprintf("; did you mean %s?", s)
			}
			return usagef("%s\n  list them with: %s checks", msg, cmdName())
		}
	}
	return nil
}

func execute(p *scanPlan, stdout, stderr io.Writer) int {
	o := p.o
	tty := cli.IsTerminal(stdout)
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
				printErr(stderr, "scan", err)
				return exitError
			}
			defer file.discard() // on early return; does nothing after commit
			out = file
		}
	}
	live := p.format == "" || o.output != ""

	if !o.quiet {
		for _, w := range p.checkSet.warnings {
			printErr(stderr, "scan", w)
		}
		for _, n := range p.notes {
			printErr(stderr, "scan", n)
		}
	}
	// Shown even with -q and machine output: a .tuner.yml can come with a
	// cloned repository or a pull request, so the log must say which file
	// steered the scan and which hosts it chose.
	if n := p.configNote(); n != "" {
		printErr(stderr, "scan", n)
	}
	// Shown even with -q: an expired ignore can fail a CI run that passed
	// yesterday. The log should say why.
	for _, ig := range p.expired {
		printErr(stderr, "scan", ig.Note())
	}

	if config.FirstRun("tuner-authorised-use") {
		fmt.Fprint(stderr, "Note: scan only sites you own or are authorised to test.\n"+
			"Tuner is non-intrusive and never sends exploit payloads. This notice is shown once.\n\n")
	}

	// The first Ctrl-C asks the scan to stop and write what it has: to
	// stdout, or to a new -o file. An -o file that already holds a report
	// keeps it, as a cut-short scan is a worse record. A second
	// one must always work, even when a target ignores cancellation, so
	// the handler goes away after the first: the next signal ends the
	// process the default way.
	var outMu sync.Mutex
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	finished := make(chan struct{})
	var watch sync.WaitGroup
	watch.Go(func() {
		select {
		case <-sigCtx.Done():
		case <-finished:
			return
		}
		stop()
		select {
		case <-finished: // the deferred stop at the end, not a signal
			return
		default:
		}
		outMu.Lock()
		printErr(stderr, "scan", "stopping... press Ctrl+C again to quit now")
		outMu.Unlock()
	})
	notice := checkForUpdate(sigCtx, p.engine.UserAgent, o.offline)

	single := len(p.targets) == 1
	views := make([]*report.Pretty, len(p.targets))
	bufs := make([]bytes.Buffer, len(p.targets)) // with several targets, each view is printed whole
	failed := make([]string, len(p.targets))     // why each target failed, or ""
	var jsonlErr error                           // the first failed --jsonl write, guarded by outMu
	rp := p.runPlan()
	outcome := scanrun.Run(sigCtx, rp, scanrun.Hooks{
		Start: func(i int, target string) engine.Hooks {
			w := stdout
			if !single {
				w = &bufs[i]
			}
			var view *report.Pretty
			if live {
				view = report.NewPretty(w, stderr, report.PrettyOptions{
					Plain: plain, Quiet: o.quiet, Progress: single && tty && !o.verbose,
				})
				view.Header(version, p.header(target))
			}

			var h engine.Hooks
			if view != nil {
				h.Fingerprint, h.Baseline, h.Progress = view.Fingerprint, view.Baseline, view.Progress
			}
			h.Finding = func(f engine.Finding) {
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
			views[i] = view
			return h
		},
		Done: func(i int, t *scanrun.Target) {
			if t.Result != nil && live {
				views[i].SetStatus(report.Status(t.Status)) // a partial scan says so above its score
				views[i].Summary(t.Result, t.Target, t.Suppressed)
			}
			outMu.Lock()
			defer outMu.Unlock()
			if !single {
				_, _ = stdout.Write(bufs[i].Bytes())
			}
			if t.Failed() {
				failed[i] = describe(t, o)
				printErr(stderr, "scan", t.Target+":", failed[i])
				if ie := (scanrun.InternalError{}); errors.As(t.Err, &ie) && o.verbose {
					_, _ = stderr.Write(ie.Stack)
				}
			}
		},
	})
	close(finished)
	watch.Wait()

	reports := outcome.Reports
	// A target that stopped early but has results is in the reports,
	// which say it is incomplete; only targets with nothing to show are
	// listed as failed.
	for i, why := range failed {
		if why != "" && outcome.Targets[i].Result == nil {
			p.write.Failed = append(p.write.Failed, report.TargetError{Target: p.targets[i], Error: why})
		}
	}
	// A file keeps its previous report unless this run has a better one.
	keep := ""
	switch {
	case file == nil:
	case outcome.Canceled && file.existed:
		keep = "scan canceled; " + o.output + " keeps the previous report"
	case len(reports) == 0 && len(p.write.Failed) > 0:
		keep = "every target failed"
	}
	werr := jsonlErr
	if werr != nil && file != nil {
		keep = "the report could not be written in full"
	}
	if keep == "" && p.format != "" && p.format != "jsonl" {
		werr = report.Write(p.format, out, reports, p.write)
	}
	switch {
	case keep != "":
		file.discard()
		printErr(stderr, "scan", "no report written:", keep)
	case werr == nil && file != nil:
		werr = file.commit()
	}
	if werr != nil {
		printErr(stderr, "scan", "writing report:", werr)
		return exitError
	}
	if keep == "" && o.output != "" && !o.quiet && len(reports) > 0 {
		fmt.Fprintf(stderr, "Report written to %s\n", o.output)
	}

	if live && !o.quiet {
		printUpdateNotice(notice, stderr)
	}

	// Shown even with -q and machine output, like the config note: an
	// untrusted .tuner.yml could hide every finding from --fail-on.
	if n := p.hiddenNote(outcome); n != "" {
		printErr(stderr, "scan", n)
	}

	exit, why := outcome.Exit(rp)
	for _, w := range why {
		printErr(stderr, "scan", w)
	}
	for _, e := range scanExtensions {
		code, err := e.Finished(p, reports, stderr)
		if err != nil {
			printErr(stderr, "scan", err)
			code = max(code, exitError)
		}
		exit = max(exit, code)
	}
	return exit
}

// configNote names the settings file in use and the targets it supplied,
// such as "using .tuner.yml, which chose the targets: https://a.example".
// It lists up to three targets; "" without a file.
func (p *scanPlan) configNote() string {
	if p.config == nil {
		return ""
	}
	if len(p.configTargets) == 0 {
		return "using " + p.config.Path
	}
	shown := p.configTargets[:min(len(p.configTargets), 3)]
	list := strings.Join(shown, ", ")
	if more := len(p.configTargets) - len(shown); more > 0 {
		list += fmt.Sprintf(" and %d more", more)
	}
	what := "target"
	if len(p.configTargets) > 1 {
		what = "targets"
	}
	return fmt.Sprintf("using %s, which chose the %s: %s", p.config.Path, what, list)
}

// hiddenNote says how many findings the config's ignore entries and the
// baseline it named hid in outcome, such as ".tuner.yml: 2 ignore entries
// hid 5 findings". It is "" when the config holds neither.
func (p *scanPlan) hiddenNote(outcome *scanrun.Outcome) string {
	if p.config == nil || (len(p.ignores) == 0 && !p.configBaseline) {
		return ""
	}
	var ignored, baselined int
	for _, t := range outcome.Targets {
		ignored += t.Ignored
		baselined += t.Suppressed - t.Ignored
	}
	var parts []string
	if len(p.ignores) > 0 {
		parts = append(parts, fmt.Sprintf("%s hid %s", plural(len(p.ignores), "ignore entry", "ignore entries"), plural(ignored, "finding", "findings")))
	}
	if p.configBaseline {
		parts = append(parts, fmt.Sprintf("the baseline %s hid %s", p.o.baseline, plural(baselined, "finding", "findings")))
	}
	return p.config.Path + ": " + strings.Join(parts, "; ")
}

// plural writes n with the singular or plural noun: "1 finding", "5 findings".
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// header is the live view's title for target: the target, then the
// config file and an automatic rate in brackets when they apply.
func (p *scanPlan) header(target string) string {
	var notes []string
	if p.config != nil {
		notes = append(notes, "config: "+p.config.Path)
	}
	if p.fast[target] {
		notes = append(notes, fmt.Sprintf("local address: %g req/s", p.rateFor(target)))
	}
	if len(notes) == 0 {
		return target
	}
	return target + " (" + strings.Join(notes, "; ") + ")"
}

// scanOne scans one target. Tests swap it to make a target hang or panic.
var scanOne = (*scanPlan).scanTarget

// runPlan is the plan package run carries out. Extensions have had their
// say by now, so it reads the targets, engine options and writer
// settings they may have changed.
func (p *scanPlan) runPlan() *scanrun.Plan {
	rp := &scanrun.Plan{
		Targets:           p.targets,
		Checks:            p.checks,
		Engine:            p.engine,
		Fast:              p.fast,
		FastRate:          localRate,
		Parallel:          p.o.parallel,
		MaxTime:           p.o.maxTime,
		Baseline:          p.baseline,
		Ignores:           p.ignores,
		FailOn:            p.failOn,
		ConfirmedOnly:     p.confirmedOnly,
		AllowMissingVulns: p.o.allowMissingVulns,
		AllowPartial:      p.o.allowPartial,
		Version:           version,
		CheckSet:          p.checkSet.source,
		Scan: func(ctx context.Context, s *engine.Scanner, target string, h engine.Hooks) (*engine.Result, error) {
			return scanOne(p, ctx, s, target, h)
		},
	}
	if p.checkSet.pack != nil {
		rp.CheckPack = p.checkSet.pack.Version
	}
	return rp
}

// The --min-confidence values. A finding is likely when its check or the
// advisor marked it low confidence, such as a CVE matched on a distro PHP
// build that may carry the fix already; every other finding is confirmed.
const (
	confidenceConfirmed = "confirmed"
	confidenceLikely    = "likely"
)

// reportFile is a report being written next to its destination. It
// replaces the destination only once complete, so a killed, canceled or
// failed run never leaves the previous report truncated. Two cron runs
// writing the same path never interleave either.
//
// The report is written in the destination's folder, so that folder must
// be writable, not just the file. A symlink is followed: the file it
// points to is replaced and the link stays. A run killed with SIGKILL
// leaves its .<name>.*.tmp file behind; the next run removes ones older
// than a day.
type reportFile struct {
	*os.File
	dest    string
	existed bool // there was a report at dest before this run
	done    bool
}

// staleReportAge is how old a leftover temporary report must be before
// createReport removes it. A day is far longer than any scan, so the
// file can't belong to one still running.
const staleReportAge = 24 * time.Hour

func createReport(dest string) (*reportFile, error) {
	shown := dest
	dest = followLinks(dest)
	fi, statErr := os.Stat(dest)
	if statErr == nil && fi.IsDir() {
		return nil, fmt.Errorf("can't write the report to %s: it is a directory", shown)
	}
	dir := filepath.Dir(dest)
	pattern := "." + filepath.Base(dest) + ".*.tmp"
	removeStale(filepath.Join(dir, pattern))
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		// The temporary name means nothing to the user.
		return nil, fmt.Errorf("can't write the report to %s: %w", dir, unwrapPath(err))
	}
	return &reportFile{File: f, dest: dest, existed: statErr == nil}, nil
}

// followLinks returns the file path names in the end, after any
// symlinks. A link whose target does not exist yet (a dangling one) is
// still followed, so the report is created where it points and the link
// stays. A loop or a chain longer than 40 links, the usual kernel limit,
// gives up and leaves path as it is.
func followLinks(path string) string {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real
	}
	cur := path
	for range 40 {
		fi, err := os.Lstat(cur)
		if err != nil {
			return cur // the end of the chain: a file that is not there yet
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			return cur
		}
		to, err := os.Readlink(cur)
		if err != nil {
			return path
		}
		if !filepath.IsAbs(to) {
			to = filepath.Join(filepath.Dir(cur), to)
		}
		cur = to
	}
	return path
}

// removeStale deletes temporary reports matching glob that are older
// than staleReportAge. Errors are ignored: the files only take space.
func removeStale(glob string) {
	names, _ := filepath.Glob(glob)
	for _, n := range names {
		if fi, err := os.Lstat(n); err == nil && fi.Mode().IsRegular() && time.Since(fi.ModTime()) > staleReportAge {
			_ = os.Remove(n)
		}
	}
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

// describe explains why a target failed. A --max-time stop and one slow
// request both wrap DeadlineExceeded; the target's status tells them
// apart.
func describe(t *scanrun.Target, o scanOptions) string {
	err := t.Err
	switch {
	case t.Status.StoppedBy == "max-time":
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

// wantsVulns reports whether a selection includes vulnerability matching:
// always, unless tags or IDs were given that leave it out.
func wantsVulns(s engine.Selector) bool {
	if slices.Contains(s.ExcludeTags, "vuln") {
		return false
	}
	advisorTags := []string{"vuln", "wordpress", "php", "outdated", "abandoned", "nginx", "apache", "core", "plugin", "theme", "composer", "known-exploited"}
	if len(s.Tags) > 0 && !slices.ContainsFunc(s.Tags, func(t string) bool { return slices.Contains(advisorTags, t) }) {
		return false
	}
	return len(s.IDs) == 0 || slices.ContainsFunc(s.IDs, engine.IsAdvisorID)
}

// httpClient builds a client for Tuner's own requests (vulnerability
// data, OSV.dev, the check pack). It goes through the scan's proxy (or
// HTTPS_PROXY and friends when there is none) and sends ua on every
// request that doesn't set its own User-Agent.
func httpClient(ua string, proxy *url.URL, timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	}
	return &http.Client{Transport: uaTransport{tr, ua}, Timeout: timeout}
}

// uaTransport fills in a default User-Agent.
type uaTransport struct {
	http.RoundTripper
	ua string
}

func (t uaTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.ua != "" && r.Header.Get("User-Agent") == "" {
		r = r.Clone(r.Context()) // a RoundTripper must not change the caller's request
		r.Header.Set("User-Agent", t.ua)
	}
	return t.RoundTripper.RoundTrip(r)
}

// vulnClient builds the vulnerability data client.
func vulnClient(ua string, proxy *url.URL, offline bool) *vulns.Client {
	return &vulns.Client{
		HTTP:      httpClient(ua, proxy, 20*time.Second),
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
