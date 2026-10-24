// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package engine runs checks against a target.
package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/matchers"
)

// Bodies beyond this size are truncated; matchers only see the first part.
const maxBody = 1 << 20

// Longest we'll honor a Retry-After header for.
const maxRetryWait = 30 * time.Second

type Options struct {
	UserAgent   string
	Headers     http.Header // sent with every request, e.g. Cookie or Authorization; overrides UserAgent
	Rate        float64     // requests per second to the target; 0 means unlimited
	Timeout     time.Duration
	Concurrency int // most requests in flight at once, for the whole scan
	Retries     int // extra attempts after a network error or a 429/503
	Proxy       *url.URL
	Insecure    bool         // skip TLS certificate verification
	Profile     Profile      // quick skips plugin and theme version lookups (not the PHP probe)
	HTTPClient  *http.Client // optional base client, e.g. one that trusts a test server
	Advisor     Advisor      // optional: known-vulnerability matching

	// FollowHost lets the scan continue on another host when the home page
	// redirects there. Headers are still only sent to the requested host.
	FollowHost bool
	// Plugins picks how hard plugin discovery tries; "" means passive.
	Plugins PluginMode
	// RequestBudget caps the requests discovery may spend; 0 means the
	// mode's default.
	RequestBudget int
	// ResponseAdvisors look at the body behind a finding, e.g. an exposed
	// composer.lock. They may add findings of their own.
	ResponseAdvisors []ResponseAdvisor
}

// PluginMode is how plugin discovery runs on a remote scan.
type PluginMode string

const (
	PluginsPassive PluginMode = "passive" // only what the site already shows: asset URLs, REST routes
	PluginsDeep    PluginMode = "deep"    // also probes readme.txt of popular plugins
)

// Advisor turns what the fingerprint found into findings, e.g. by matching
// versions against a vulnerability database. It runs alongside the checks.
type Advisor interface {
	Advise(ctx context.Context, base *url.URL, fp fingerprint.Result) (findings []Finding, warnings []string)
}

// StatusAdvisor is an Advisor that also says how complete its data was,
// reported as Result.VulnData: ok, partial, missing or off.
type StatusAdvisor interface {
	Advisor
	AdviseStatus(ctx context.Context, base *url.URL, fp fingerprint.Result) (findings []Finding, warnings []string, status string)
}

// ResponseAdvisor sees the body of a finding's response and may add
// findings, e.g. known-vulnerable packages in an exposed composer.lock.
type ResponseAdvisor interface {
	AdviseResponse(ctx context.Context, f Finding, body []byte) (findings []Finding, warnings []string)
}

// Confidence says whether a finding is confirmed or only likely. The JSON
// values are "high" and "low".
type Confidence string

const (
	ConfidenceHigh Confidence = "high" // confirmed
	ConfidenceLow  Confidence = "low"  // likely, e.g. a version a distro may have patched
)

// Confirmed reports whether the finding is confirmed rather than likely.
// Anything but "low" counts as confirmed, matching how checks default.
func (c Confidence) Confirmed() bool { return c != ConfidenceLow }

// Advisory is one known vulnerability behind an advisor finding.
type Advisory struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	CVEs       []string `json:"cves,omitempty"`
	Severity   Severity `json:"severity,omitempty"` // empty when unrated
	CVSS       float64  `json:"cvss,omitempty"`
	KEV        bool     `json:"kev,omitempty"` // known exploited (CISA KEV)
	FixedIn    string   `json:"fixed_in,omitempty"`
	References []string `json:"references,omitempty"`
}

// Hooks stream progress while a scan runs. Calls are never concurrent.
type Hooks struct {
	Fingerprint func(fingerprint.Result)
	Baseline    func(soft404 bool)
	Finding     func(Finding)
	Progress    func(done, total int)
	Request     func(RequestLog)
}

// RequestLog describes one HTTP exchange, for verbose output.
type RequestLog struct {
	Method   string
	URL      string
	Status   int
	Duration time.Duration
	Attempt  int
	Err      error
}

type Finding struct {
	ID         string     `json:"id"`
	Title      string     `json:"title"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Caveat     string     `json:"caveat,omitempty"` // why confidence is low, e.g. "a distro build may already include the fix"
	Target     string     `json:"target"`
	URL        string     `json:"url"`
	Path       string     `json:"path"`
	Evidence   Evidence   `json:"evidence"`
	Impact     string     `json:"impact,omitempty"`
	Fix        string     `json:"fix,omitempty"`
	References []string   `json:"references,omitempty"`
	Tags       []string   `json:"tags,omitempty"`
	Advisories []Advisory `json:"advisories,omitempty"`
	Source     string     `json:"source,omitempty"` // data provider, for attribution

	Fingerprint string            `json:"fingerprint,omitempty"` // stable identity for baselines, set by report.Stamp
	Fixes       map[string]string `json:"fixes,omitempty"`       // server config snippets by server: nginx, apache
	Line        int               `json:"line,omitempty"`        // 1-based line in a local file
}

// Evidence shows why a finding fired. Secrets in it are always masked.
type Evidence struct {
	Request string            `json:"request"`
	Status  int               `json:"status"`
	Matched []string          `json:"matched,omitempty"`
	Secrets []matchers.Secret `json:"secrets,omitempty"`
}

type Result struct {
	Target      string             `json:"target"`
	Fingerprint fingerprint.Result `json:"fingerprint"`
	Soft404     bool               `json:"soft_404"`
	TLS         *matchers.TLSInfo  `json:"tls,omitempty"`
	Score       int                `json:"score"`
	Checks      int                `json:"checks"`
	Requests    int64              `json:"requests"`
	Errors      int64              `json:"errors"`
	Throttled   int64              `json:"throttled"` // 429/503 replies that made Tuner slow down
	Duration    time.Duration      `json:"-"`
	Findings    []Finding          `json:"findings"`
	Warnings    []string           `json:"warnings,omitempty"`

	// Complete is true when every planned request ran. StoppedBy says why
	// not: interrupted, max-time, waf, home-status or budget.
	Complete  bool   `json:"complete"`
	StoppedBy string `json:"stopped_by,omitempty"`
	BlockedBy string `json:"blocked_by,omitempty"` // WAF or bot wall in the way, e.g. cloudflare
	VulnData  string `json:"vuln_data,omitempty"`  // ok, partial, missing or off
}

// Counts returns the number of findings per severity.
func (r *Result) Counts() map[Severity]int {
	c := map[Severity]int{}
	for _, f := range r.Findings {
		c[f.Severity]++
	}
	return c
}

// Worst returns the most severe finding's severity, or "" if there are none.
func (r *Result) Worst() Severity {
	var w Severity
	for _, f := range r.Findings {
		if w == "" || f.Severity.Rank() < w.Rank() {
			w = f.Severity
		}
	}
	return w
}

type Scanner struct {
	checks  []*Check
	opts    Options
	resolve resolver // host lookups for the address guard; tests stub it
}

func New(checks []*Check, opts Options) *Scanner {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	return &Scanner{checks: checks, opts: opts, resolve: defaultResolve}
}

// Scan fingerprints target, learns its soft-404 behavior, then runs every
// applicable check. Findings stream through h as they are found.
func (s *Scanner) Scan(ctx context.Context, target string, h Hooks) (*Result, error) {
	start := time.Now()
	ss, home, err := s.open(ctx, target, h)
	if err != nil {
		return nil, err
	}

	home.TLS = ss.tlsInfo(ctx, home)
	res := &Result{Target: ss.base.Redacted(), Fingerprint: fingerprint.Detect(home), TLS: home.TLS, Warnings: ss.warnings}
	// A blocked or failing home page still gets scanned, since some checks
	// may get through. The result is marked partial.
	if v := detectWAF(home); v != nil {
		res.BlockedBy, res.StoppedBy = v.id, "waf"
		res.Warnings = append(res.Warnings, blockedWarning(v, ""))
	} else if home.Status < 200 || home.Status > 399 {
		res.StoppedBy = "home-status"
		res.Warnings = append(res.Warnings, homeStatusWarning(home.Status))
	}
	// The PHP probe runs in every profile: it costs at most three requests,
	// and without it quick scans would report the version as hidden behind
	// a page cache.
	var php, phpBuild, phpSource string
	var vwg sync.WaitGroup
	vwg.Go(func() { php, phpBuild, phpSource = ss.probePHP(ctx, &res.Fingerprint) })
	if s.opts.Profile != ProfileQuick {
		vwg.Go(func() { ss.resolveVersions(ctx, &res.Fingerprint) })
	}
	vwg.Wait()
	switch {
	case php != "":
		res.Fingerprint.PHP, res.Fingerprint.PHPBuild, res.Fingerprint.PHPSource = php, phpBuild, phpSource
	case phpSource != "" && res.Fingerprint.PHPSource == "":
		res.Fingerprint.PHPSource = phpSource
	}
	ss.emit(func() {
		if h.Fingerprint != nil {
			h.Fingerprint(res.Fingerprint)
		}
	})

	res.Soft404 = ss.soft404(ctx)
	// The baseline hook tells the user whether the server sends real 404s.
	// Behind a block page that answer is the firewall's, not the site's,
	// so it is left out rather than reported wrong.
	if res.StoppedBy == "" && !ss.baselineBlocked(ctx) {
		ss.emit(func() {
			if h.Baseline != nil {
				h.Baseline(res.Soft404)
			}
		})
	}

	var jobs []job
	for _, c := range s.checks {
		if !slices.ContainsFunc(c.Requires, func(t string) bool { return !res.Fingerprint.Has(t) }) {
			res.Checks++
			for _, p := range c.Request.Path {
				jobs = append(jobs, job{c, strings.ReplaceAll(p, "{{host}}", ss.base.Hostname())})
			}
		}
	}
	ss.plan(jobs)

	var done atomic.Int64
	var wg sync.WaitGroup
	if s.opts.Advisor != nil {
		wg.Go(func() {
			findings, warnings := s.opts.Advisor.Advise(ctx, ss.base, res.Fingerprint)
			ss.emit(func() {
				res.Warnings = append(res.Warnings, warnings...)
				for _, f := range findings {
					f.Target = res.Target
					res.Findings = append(res.Findings, f)
					if h.Finding != nil {
						h.Finding(f)
					}
				}
			})
		})
	}
	ch := make(chan job)
	for range s.opts.Concurrency {
		wg.Go(func() {
			for j := range ch {
				f, ok := ss.run(ctx, j.c, j.path)
				ss.finished(j)
				n := int(done.Add(1))
				ss.emit(func() {
					if ok {
						f.Target = res.Target
						res.Findings = append(res.Findings, f)
						if h.Finding != nil {
							h.Finding(f)
						}
					}
					if h.Progress != nil {
						h.Progress(n, len(jobs))
					}
				})
			}
		})
	}
feed:
	for _, j := range jobs {
		select {
		case ch <- j:
		case <-ctx.Done():
			break feed
		}
	}
	close(ch)
	wg.Wait()

	SortFindings(res.Findings)
	res.Score = Score(res.Findings)
	res.Requests = ss.requests.Load()
	res.Errors = ss.errors.Load()
	res.Throttled = ss.throttled.Load()
	res.Duration = time.Since(start)
	if res.BlockedBy == "" {
		if v, n, seen := ss.waf.mostlyBlocked(); v != nil {
			res.BlockedBy, res.StoppedBy = v.id, "waf"
			res.Warnings = append(res.Warnings, blockedWarning(v, fmt.Sprintf(" on %d of %d check requests", n, seen)))
		}
	}
	res.Complete = ctx.Err() == nil && res.StoppedBy == ""
	return res, ctx.Err()
}

// SortFindings orders findings for reports: most severe first, confirmed
// before likely within a severity, then by ID and path.
func SortFindings(fs []Finding) {
	slices.SortStableFunc(fs, func(a, b Finding) int {
		if d := a.Severity.Rank() - b.Severity.Rank(); d != 0 {
			return d
		}
		if ac, bc := a.Confidence.Confirmed(), b.Confidence.Confirmed(); ac != bc {
			if bc {
				return 1
			}
			return -1
		}
		return strings.Compare(a.ID+a.Path, b.ID+b.Path)
	})
}

// job is one check request: a check and one of its paths.
type job struct {
	c    *Check
	path string
}

// keys returns the cache keys j reads: its own response and, when the
// check compares against the soft-404 page, the probe for its path.
func (ss *session) keys(j job) []string {
	k := []string{j.c.Request.Method + " " + j.path}
	if j.c.Match.NeedsBaseline() {
		k = append(k, "GET "+probePath(j.path, ss.token))
	}
	return k
}

// plan counts how many jobs read each cached response, so finished can
// drop a body once nothing needs it. A scan against a site that answers
// every path with a 1 MiB page would otherwise keep all of them until it
// ends. The home page and the soft-404 probe stay pinned. Bodies already
// fetched that no job reads (version lookups, the PHP probe) go now.
func (ss *session) plan(jobs []job) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.uses = map[string]int{"GET /": 1, "GET " + probePath("/x", ss.token): 1}
	for _, j := range jobs {
		for _, k := range ss.keys(j) {
			ss.uses[k]++
		}
	}
	for k, f := range ss.cache {
		if ss.uses[k] == 0 {
			ss.drop(f)
		}
	}
}

// finished releases what job j read, dropping bodies it was the last
// reader of. Anything that needs a body, such as Options.ResponseAdvisors,
// must run inside the job before this.
func (ss *session) finished(j job) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for _, k := range ss.keys(j) {
		if ss.uses[k]--; ss.uses[k] == 0 {
			if f := ss.cache[k]; f != nil {
				ss.drop(f)
			}
		}
	}
}

// drop replaces a cached response with a copy without its body. Status,
// headers, Size and SHA256 stay. Callers hold ss.mu.
func (ss *session) drop(f *fetch) {
	f.dropped = true
	if f.resp != nil && f.resp.Body != nil {
		r := *f.resp
		r.Body = nil
		f.resp = &r
	}
}

func (ss *session) run(ctx context.Context, c *Check, p string) (Finding, bool) {
	r, err := ss.get(ctx, c.Request.Method, p)
	if err != nil {
		return Finding{}, false
	}
	// A block page says nothing about the site behind it.
	v := detectWAF(r)
	ss.waf.add(v)
	if v != nil {
		return Finding{}, false
	}
	ok, ev := c.Match.Match(r, func() bool { return ss.isBaseline(ctx, c, p, r) })
	if !ok {
		return Finding{}, false
	}
	// Matchers already redact before cutting evidence; this second pass
	// covers evidence they build from other sources.
	for i := range ev {
		ev[i] = matchers.Redact(ev[i])
	}
	f := Finding{
		ID:         c.ID,
		Title:      c.Name,
		Severity:   c.Severity,
		Confidence: c.Confidence,
		URL:        r.URL.Redacted(),
		Path:       p,
		Evidence:   Evidence{Request: c.Request.Method + " " + p, Status: r.Status, Matched: ev},
		Impact:     strings.TrimSpace(c.Impact),
		Fix:        strings.TrimSpace(c.Fix),
		References: c.References,
		Tags:       c.Tags,
		Fixes:      c.FixServer.fixes(),
	}
	if c.Extract.Secrets {
		f.Evidence.Secrets = matchers.FindSecrets(r.Body)
	}
	return f, true
}

// session is the state of one scan against one target.
type session struct {
	opts     Options
	hooks    Hooks
	hookMu   sync.Mutex
	follow   *http.Client // follows redirects, used for the home page
	client   *http.Client // never follows redirects, used for checks
	origin   *url.URL     // scheme and host the user asked for; user headers only go here
	base     *url.URL     // where checks are sent: origin, or where its home page led
	headers  http.Header  // the user's headers, plus basic auth from the target URL
	resolve  resolver
	dial     dialFunc // guarded raw dialer for the TLS probe
	warnings []string
	lim      *limiter
	// inflight holds one token per HTTP exchange in progress. Every request
	// of the scan (checks, soft-404 probes, version lookups, the PHP and
	// TLS probes) takes one, so -c is a hard cap however the work is split.
	inflight chan struct{}
	token    string         // random path segment for soft-404 probes
	roots    *x509.CertPool // trust store for the TLS probe; nil means the system's
	proxied  bool           // requests go through a proxy, so raw TLS dials would bypass it
	// internalOK is set when the target itself is loopback, link-local or
	// private; otherwise connections to such addresses are refused.
	internalOK bool
	mu         sync.Mutex
	cache      map[string]*fetch
	uses       map[string]int // jobs still to read each cache key, see plan
	waf        wafTally       // check responses that were block pages
	requests   atomic.Int64
	errors     atomic.Int64
	throttled  atomic.Int64
}

type fetch struct {
	once    sync.Once
	resp    *matchers.Response
	err     error
	dropped bool // the body is gone; a later get fetches it again
}

// emit runs a hook callback, never two at once.
func (ss *session) emit(fn func()) {
	ss.hookMu.Lock()
	defer ss.hookMu.Unlock()
	fn()
}

func (s *Scanner) open(ctx context.Context, target string, h Hooks) (*session, *matchers.Response, error) {
	u, explicit, auth, err := ParseTargetAuth(target)
	if err != nil {
		return nil, nil, err
	}
	headers := s.opts.Headers.Clone()
	if headers == nil {
		headers = http.Header{}
	}
	// An explicit -H Authorization wins over credentials in the URL.
	if auth != "" && headers.Get("Authorization") == "" {
		headers.Set("Authorization", auth)
	}
	base := s.opts.HTTPClient
	if base == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.MaxIdleConnsPerHost = s.opts.Concurrency
		if s.opts.Proxy != nil {
			tr.Proxy = http.ProxyURL(s.opts.Proxy)
		}
		if s.opts.Insecure {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // the user asked for --insecure
		}
		base = &http.Client{Transport: tr}
	}
	var roots *x509.CertPool
	proxied := false
	if tr, ok := base.Transport.(*http.Transport); ok {
		if tr.TLSClientConfig != nil {
			roots = tr.TLSClientConfig.RootCAs
		}
		if tr.Proxy != nil {
			p, _ := tr.Proxy(&http.Request{URL: u})
			proxied = p != nil
		}
	}
	ss := &session{
		opts:     s.opts,
		hooks:    h,
		headers:  headers,
		resolve:  s.resolve,
		roots:    roots,
		proxied:  proxied,
		lim:      newLimiter(s.opts.Rate),
		inflight: make(chan struct{}, s.opts.Concurrency),
		token:    "rhythm-tuner-" + randHex(6),
		cache:    map[string]*fetch{},
	}
	ss.internalOK = ss.internalHost(ctx, u.Hostname())
	ss.dial = ss.guardDial((&net.Dialer{Timeout: s.opts.Timeout}).DialContext)
	follow, noFollow := *base, *base
	follow.Transport = ss.guardTransport(base.Transport)
	noFollow.Transport = follow.Transport
	follow.Timeout, noFollow.Timeout = s.opts.Timeout, s.opts.Timeout
	follow.CheckRedirect = ss.checkRedirect
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ss.follow, ss.client = &follow, &noFollow

	ss.origin = &url.URL{Scheme: u.Scheme, Host: u.Host}
	home, err := ss.do(ctx, ss.follow, "GET", u.String())
	if err != nil && !explicit && ctx.Err() == nil && !errors.As(err, new(*RedirectError)) {
		u.Scheme = "http"
		ss.origin.Scheme = "http"
		home, err = ss.do(ctx, ss.follow, "GET", u.String())
	}
	if err != nil {
		var cv *tls.CertificateVerificationError
		var re *RedirectError
		switch {
		case errors.As(err, &re):
			return nil, nil, re
		case errors.As(err, &cv):
			return nil, nil, fmt.Errorf("can't reach %s: invalid TLS certificate: %w (rerun with --insecure to scan anyway)", u.Host, cv.Err)
		}
		return nil, nil, fmt.Errorf("can't reach %s: %w", u.Host, err)
	}
	// checkRedirect already refused other hosts; this guards against a
	// caller's client that bypassed it.
	if !sameSite(ss.origin, home.URL) {
		if !s.opts.FollowHost {
			return nil, nil, &RedirectError{From: ss.origin, To: home.URL}
		}
		w := fmt.Sprintf("%s redirects to %s; scanning %s because of --follow-host", ss.origin.Host, home.URL.Host, home.URL.Host)
		if len(ss.headers) > 0 {
			w += ", without your headers and cookies"
		}
		ss.warnings = append(ss.warnings, w)
	}
	// Keep the scheme and host we were redirected to (http→https, apex→www)
	// but the path the user asked for, so /blog scans stay under /blog.
	ss.base = &url.URL{Scheme: home.URL.Scheme, Host: home.URL.Host, Path: strings.TrimSuffix(u.Path, "/")}
	f := &fetch{}
	f.once.Do(func() { f.resp = home })
	ss.cache["GET /"] = f
	return ss, home, nil
}

// ParseTarget accepts a URL or bare hostname. explicitScheme is false when
// the scheme was guessed, in which case Scan falls back from https to http.
// Credentials in the URL are dropped from u; ParseTargetAuth returns them.
func ParseTarget(target string) (u *url.URL, explicitScheme bool, err error) {
	u, explicitScheme, _, err = ParseTargetAuth(target)
	return u, explicitScheme, err
}

// ParseTargetAuth is ParseTarget that also turns user:password@ in the URL
// into an Authorization header value. The returned URL never carries
// them, so they can't reach findings, logs or error messages; Scan sends
// the header with every request to the target instead of only the first.
func ParseTargetAuth(target string) (u *url.URL, explicitScheme bool, authorization string, err error) {
	explicitScheme = strings.Contains(target, "://")
	if !explicitScheme {
		target = "https://" + target
	}
	u, err = url.Parse(target)
	if err != nil || u.Host == "" {
		return nil, false, "", fmt.Errorf("%q is not a valid URL or hostname", redactUserinfo(target))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, false, "", fmt.Errorf("unsupported scheme %q, use http or https", u.Scheme)
	}
	if u.User != nil {
		pass, _ := u.User.Password()
		authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pass))
		u.User = nil
	}
	return u, explicitScheme, authorization, nil
}

// redactUserinfo masks the password in a URL that may not parse, the way
// url.URL.Redacted does for one that does.
func redactUserinfo(raw string) string {
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return raw
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	at := strings.LastIndex(rest[:end], "@")
	if at < 0 {
		return raw
	}
	user, _, hasPass := strings.Cut(rest[:at], ":")
	if hasPass {
		user += ":xxxxx"
	}
	return scheme + "://" + user + rest[at:]
}

// RedactURL masks the password in a URL or target string, like
// url.URL.Redacted, even when it does not parse. Use it wherever a target
// the user typed is printed.
func RedactURL(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Redacted()
	}
	return redactUserinfo(raw)
}

// get fetches a path relative to the target once per scan; later calls
// for the same method and path reuse the response.
func (ss *session) get(ctx context.Context, method, p string) (*matchers.Response, error) {
	key := method + " " + p
	ss.mu.Lock()
	f := ss.cache[key]
	// A dropped body only gets asked for again by a reader plan did not
	// count; fetching again beats handing it an empty body.
	if f == nil || f.dropped {
		f = &fetch{}
		ss.cache[key] = f
	}
	ss.mu.Unlock()
	f.once.Do(func() { f.resp, f.err = ss.do(ctx, ss.client, method, ss.base.String()+p) })
	// drop may swap f.resp after the last planned reader, so read it under
	// the same lock.
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return f.resp, f.err
}

// do sends one request, retrying network errors and 429/503 replies. A
// throttling reply also slows the rate for the rest of the scan.
func (ss *session) do(ctx context.Context, c *http.Client, method, u string) (*matchers.Response, error) {
	for attempt := 0; ; attempt++ {
		r, retryIn, err := ss.attempt(ctx, c, method, u, attempt)
		if retryIn == 0 || attempt >= ss.opts.Retries || ctx.Err() != nil {
			if err != nil {
				ss.errors.Add(1)
			}
			return r, err
		}
		if err := sleep(ctx, retryIn); err != nil {
			return nil, err
		}
	}
}

// attempt returns a non-zero retryIn when the request is worth repeating.
func (ss *session) attempt(ctx context.Context, c *http.Client, method, u string, n int) (_ *matchers.Response, retryIn time.Duration, _ error) {
	if err := ss.lim.wait(ctx); err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, 0, err
	}
	// Held until the body is read, so a slow body counts as in flight;
	// released before do sleeps for a retry.
	if err := ss.acquire(ctx); err != nil {
		return nil, 0, err
	}
	defer ss.release()
	if host := ss.setHeaders(req.Header, req.URL); host != "" {
		req.Host = host
	}

	ss.requests.Add(1)
	start := time.Now()
	resp, err := c.Do(req)
	log := RequestLog{Method: method, URL: RedactURL(u), Duration: time.Since(start), Attempt: n + 1, Err: err}
	if err != nil {
		ss.logRequest(log)
		if ctx.Err() != nil {
			return nil, 0, err
		}
		return nil, backoff(n), err
	}
	defer func() { _ = resp.Body.Close() }()
	log.Status = resp.StatusCode
	ss.logRequest(log)

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		ss.throttled.Add(1)
		ss.lim.slow()
		retryIn = retryAfter(resp.Header.Get("Retry-After"), n)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, backoff(n), err
	}
	return &matchers.Response{
		URL: resp.Request.URL, Status: resp.StatusCode, Header: resp.Header, Body: body, TLSState: resp.TLS,
		Size: len(body), SHA256: sha256.Sum256(body),
	}, retryIn, nil
}

// acquire waits for a free request slot, see session.inflight.
func (ss *session) acquire(ctx context.Context) error {
	select {
	case ss.inflight <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (ss *session) release() { <-ss.inflight }

func (ss *session) logRequest(l RequestLog) {
	if ss.hooks.Request != nil {
		ss.emit(func() { ss.hooks.Request(l) })
	}
}

// backoff is the wait before retry n+1 after a network error.
func backoff(n int) time.Duration { return time.Duration(n+1) * 500 * time.Millisecond }

// retryAfter parses a Retry-After header (seconds or HTTP date), falling
// back to exponential backoff, capped at maxRetryWait.
func retryAfter(h string, n int) time.Duration {
	d := time.Second << n
	if secs, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && secs >= 0 {
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(h); err == nil {
		d = time.Until(t)
	}
	return min(max(d, 100*time.Millisecond), maxRetryWait)
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// limiter spaces requests evenly to stay under a requests-per-second cap.
type limiter struct {
	mu    sync.Mutex
	every time.Duration
	next  time.Time
}

// Slowest pace the limiter backs off to after repeated throttling.
const slowest = 2 * time.Second

func newLimiter(rps float64) *limiter {
	if rps <= 0 {
		return nil
	}
	return &limiter{every: time.Duration(float64(time.Second) / rps)}
}

func (l *limiter) wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	at := l.next
	if at.Before(now) {
		at = now
	}
	l.next = at.Add(l.every)
	l.mu.Unlock()
	return sleep(ctx, time.Until(at))
}

// slow halves the request rate, down to one request every two seconds.
func (l *limiter) slow() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.every = min(l.every*2, slowest)
	l.mu.Unlock()
}
