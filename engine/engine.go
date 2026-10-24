// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package engine runs checks against a target.
package engine

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	Concurrency int
	Retries     int // extra attempts after a network error or a 429/503
	Proxy       *url.URL
	Insecure    bool         // skip TLS certificate verification
	Profile     Profile      // quick skips plugin and theme version lookups (not the PHP probe)
	HTTPClient  *http.Client // optional base client, e.g. one that trusts a test server
	Advisor     Advisor      // optional: known-vulnerability matching
}

// Advisor turns what the fingerprint found into findings, e.g. by matching
// versions against a vulnerability database. It runs alongside the checks.
type Advisor interface {
	Advise(ctx context.Context, base *url.URL, fp fingerprint.Result) (findings []Finding, warnings []string)
}

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
	Confidence string     `json:"confidence"`
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
	checks []*Check
	opts   Options
}

func New(checks []*Check, opts Options) *Scanner {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	return &Scanner{checks: checks, opts: opts}
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
	res := &Result{Target: ss.base.String(), Fingerprint: fingerprint.Detect(home), TLS: home.TLS}
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
	if php != "" {
		res.Fingerprint.PHP, res.Fingerprint.PHPBuild, res.Fingerprint.PHPSource = php, phpBuild, phpSource
	}
	ss.emit(func() {
		if h.Fingerprint != nil {
			h.Fingerprint(res.Fingerprint)
		}
	})

	res.Soft404 = ss.soft404(ctx)
	ss.emit(func() {
		if h.Baseline != nil {
			h.Baseline(res.Soft404)
		}
	})

	type job struct {
		c    *Check
		path string
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

	slices.SortStableFunc(res.Findings, func(a, b Finding) int {
		if d := a.Severity.Rank() - b.Severity.Rank(); d != 0 {
			return d
		}
		// Confirmed findings before "likely" ones within a severity.
		if al, bl := a.Confidence == "low", b.Confidence == "low"; al != bl {
			if al {
				return 1
			}
			return -1
		}
		return strings.Compare(a.ID+a.Path, b.ID+b.Path)
	})
	res.Score = Score(res.Findings)
	res.Requests = ss.requests.Load()
	res.Errors = ss.errors.Load()
	res.Throttled = ss.throttled.Load()
	res.Duration = time.Since(start)
	return res, ctx.Err()
}

func (ss *session) run(ctx context.Context, c *Check, p string) (Finding, bool) {
	r, err := ss.get(ctx, c.Request.Method, p)
	if err != nil {
		return Finding{}, false
	}
	ok, ev := c.Match.Match(r, func() bool { return ss.isBaseline(ctx, p, r) })
	if !ok {
		return Finding{}, false
	}
	for i := range ev {
		ev[i] = matchers.Redact(ev[i])
	}
	f := Finding{
		ID:         c.ID,
		Title:      c.Name,
		Severity:   c.Severity,
		Confidence: c.Confidence,
		URL:        r.URL.String(),
		Path:       p,
		Evidence:   Evidence{Request: c.Request.Method + " " + p, Status: r.Status, Matched: ev},
		Impact:     strings.TrimSpace(c.Impact),
		Fix:        strings.TrimSpace(c.Fix),
		References: c.References,
		Tags:       c.Tags,
	}
	if c.Extract.Secrets {
		f.Evidence.Secrets = matchers.FindSecrets(r.Body)
	}
	return f, true
}

// session is the state of one scan against one target.
type session struct {
	opts      Options
	hooks     Hooks
	hookMu    sync.Mutex
	follow    *http.Client // follows redirects, used for the home page
	client    *http.Client // never follows redirects, used for checks
	base      *url.URL
	lim       *limiter
	token     string         // random path segment for soft-404 probes
	roots     *x509.CertPool // trust store for the TLS probe; nil means the system's
	proxied   bool           // requests go through a proxy, so raw TLS dials would bypass it
	mu        sync.Mutex
	cache     map[string]*fetch
	requests  atomic.Int64
	errors    atomic.Int64
	throttled atomic.Int64
}

type fetch struct {
	once sync.Once
	resp *matchers.Response
	err  error
}

// emit runs a hook callback, never two at once.
func (ss *session) emit(fn func()) {
	ss.hookMu.Lock()
	defer ss.hookMu.Unlock()
	fn()
}

func (s *Scanner) open(ctx context.Context, target string, h Hooks) (*session, *matchers.Response, error) {
	u, explicit, err := ParseTarget(target)
	if err != nil {
		return nil, nil, err
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
	follow, noFollow := *base, *base
	follow.Timeout, noFollow.Timeout = s.opts.Timeout, s.opts.Timeout
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	ss := &session{
		opts:    s.opts,
		hooks:   h,
		follow:  &follow,
		client:  &noFollow,
		roots:   roots,
		proxied: proxied,
		lim:     newLimiter(s.opts.Rate),
		token:   "rhythm-tuner-" + randHex(6),
		cache:   map[string]*fetch{},
	}

	home, err := ss.do(ctx, ss.follow, "GET", u.String())
	if err != nil && !explicit && ctx.Err() == nil {
		u.Scheme = "http"
		home, err = ss.do(ctx, ss.follow, "GET", u.String())
	}
	if err != nil {
		var cv *tls.CertificateVerificationError
		if errors.As(err, &cv) {
			return nil, nil, fmt.Errorf("can't reach %s: invalid TLS certificate: %w (rerun with --insecure to scan anyway)", u.Host, cv.Err)
		}
		return nil, nil, fmt.Errorf("can't reach %s: %w", u.Host, err)
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
func ParseTarget(target string) (u *url.URL, explicitScheme bool, err error) {
	explicitScheme = strings.Contains(target, "://")
	if !explicitScheme {
		target = "https://" + target
	}
	u, err = url.Parse(target)
	if err != nil || u.Host == "" {
		return nil, false, fmt.Errorf("%q is not a valid URL or hostname", target)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, false, fmt.Errorf("unsupported scheme %q, use http or https", u.Scheme)
	}
	return u, explicitScheme, nil
}

// get fetches a path relative to the target once per scan; later calls
// for the same method and path reuse the response.
func (ss *session) get(ctx context.Context, method, p string) (*matchers.Response, error) {
	key := method + " " + p
	ss.mu.Lock()
	f := ss.cache[key]
	if f == nil {
		f = &fetch{}
		ss.cache[key] = f
	}
	ss.mu.Unlock()
	f.once.Do(func() { f.resp, f.err = ss.do(ctx, ss.client, method, ss.base.String()+p) })
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
	req.Header.Set("User-Agent", ss.opts.UserAgent)
	for k, vs := range ss.opts.Headers {
		if strings.EqualFold(k, "Host") {
			req.Host = vs[0]
			continue
		}
		req.Header[k] = vs
	}

	ss.requests.Add(1)
	start := time.Now()
	resp, err := c.Do(req)
	log := RequestLog{Method: method, URL: u, Duration: time.Since(start), Attempt: n + 1, Err: err}
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
	return &matchers.Response{URL: resp.Request.URL, Status: resp.StatusCode, Header: resp.Header, Body: body, TLSState: resp.TLS}, retryIn, nil
}

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
