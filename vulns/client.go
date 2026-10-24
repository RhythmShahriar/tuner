// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package vulns matches detected WordPress core, plugins, themes, PHP and
// web server versions against known vulnerabilities.
//
// Vulnerability data comes from WPVulnerability (wpvulnerability.com),
// public domain under CC0 1.0, which aggregates CVE, Wordfence, WPScan and
// Patchstack. With an API key, the Wordfence Intelligence feed is a second
// source, merged by CVE (see Wordfence). Latest-release data comes from
// the wordpress.org API, and
// PHP's supported branches from php.net. Every
// lookup is cached on disk and refreshed automatically once it is older
// than the TTL; when the network is unavailable, stale data is used.
package vulns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/vulns/cache"
	"github.com/RhythmShahriar/tuner/vulns/ratelimit"
)

const (
	DefaultVulnBase   = "https://www.wpvulnerability.net"
	DefaultWPOrgBase  = "https://api.wordpress.org"
	DefaultPHPNetBase = "https://www.php.net"
	DefaultTTL        = 24 * time.Hour
	DefaultTimeout    = 10 * time.Second

	// Attribution shown with every vulnerability finding.
	Source = "WPVulnerability (wpvulnerability.com, CC0)"
)

// ErrOffline means the data isn't cached and --offline forbids fetching it.
var ErrOffline = cache.ErrOffline

// ErrOldCache means the only cached copy was written by an older Tuner,
// which normalised records differently; --offline forbids refetching it.
var ErrOldCache = cache.ErrOldFormat

// cacheFormat versions the records on disk. Bump it whenever normalize
// changes what a record holds, so entries an older Tuner wrote are fetched
// again instead of living on under --offline or a restored CI cache.
const cacheFormat = 1

type Client struct {
	HTTP       *http.Client
	UserAgent  string
	CacheDir   string        // "" disables the disk cache
	TTL        time.Duration // refresh records older than this; 0 means DefaultTTL
	Offline    bool          // never fetch; use cached data however old
	Force      bool          // always fetch, ignoring the TTL (rhythm tuner update)
	Pace       time.Duration // gap between requests to the data services; 0 means 200ms, <0 none
	Timeout    time.Duration // per request, reading the answer included; 0 means DefaultTimeout
	VulnBase   string
	WPOrgBase  string
	PHPNetBase string
	// Wordfence, when set, adds the Wordfence Intelligence feed as a
	// second source for plugins, themes and core, merged by CVE.
	Wordfence *Wordfence

	lim     *ratelimit.Limiter
	breaker ratelimit.Breaker
	http    *http.Client
	store   *cache.Store
	once    sync.Once
}

// DefaultCacheDir is ~/.cache/rhythm/tuner/vulns (or the OS equivalent).
func DefaultCacheDir() string {
	d, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "rhythm", "tuner", "vulns")
}

func (c *Client) init() {
	c.once.Do(func() {
		// Connections give up after a few seconds: a firewalled data
		// service must not hold the scan for the OS connect timeout.
		c.http = ratelimit.FastClient(c.HTTP)
		if c.Timeout <= 0 {
			c.Timeout = DefaultTimeout
		}
		if c.TTL <= 0 {
			c.TTL = DefaultTTL
		}
		if c.VulnBase == "" {
			c.VulnBase = DefaultVulnBase
		}
		if c.WPOrgBase == "" {
			c.WPOrgBase = DefaultWPOrgBase
		}
		if c.PHPNetBase == "" {
			c.PHPNetBase = DefaultPHPNetBase
		}
		switch {
		case c.Pace == 0:
			c.lim = ratelimit.New(5) // one request every 200ms: be polite to free services
		case c.Pace > 0:
			c.lim = ratelimit.New(float64(time.Second) / float64(c.Pace))
		}
		c.store = &cache.Store{Dir: c.CacheDir, TTL: c.TTL, Offline: c.Offline, Force: c.Force, Format: cacheFormat}
	})
}

// Record is the normalized vulnerability data for one component.
type Record struct {
	Name         string `json:"name,omitempty"`
	Closed       bool   `json:"closed,omitempty"`
	ClosedReason string `json:"closed_reason,omitempty"`
	ClosedDate   string `json:"closed_date,omitempty"`
	EndOfLife    string `json:"end_of_life,omitempty"` // PHP and server branches: support end date
	Vulns        []Vuln `json:"vulns"`
}

// Vuln is one advisory. Min/Max bound the affected versions; an empty
// bound is open. Core records come pre-filtered and have no bounds.
type Vuln struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	CVEs        []string `json:"cves,omitempty"`
	Severity    string   `json:"severity,omitempty"` // critical, high, medium, low; empty if unrated
	CVSS        float64  `json:"cvss,omitempty"`
	Vector      string   `json:"vector,omitempty"`
	KEV         bool     `json:"kev,omitempty"` // in CISA's Known Exploited Vulnerabilities catalog
	Min         string   `json:"min,omitempty"`
	MinOp       string   `json:"min_op,omitempty"`
	Max         string   `json:"max,omitempty"`
	MaxOp       string   `json:"max_op,omitempty"`
	Unfixed     bool     `json:"unfixed,omitempty"`
	References  []string `json:"references,omitempty"`
	Published   string   `json:"published,omitempty"`
	Sources     []string `json:"sources,omitempty"` // SourceWPVulnerability, SourceWordfence; set when merged
}

// Valid reports whether r holds a usable record; a cache entry without
// one is fetched again.
func (r *Record) Valid() bool { return r != nil && r.Vulns != nil }

// Affects reports whether version v is in the vulnerable range.
func (v Vuln) Affects(version string) bool {
	return satisfies(version, v.MinOp, v.Min) && satisfies(version, v.MaxOp, v.Max)
}

// FixedIn is the first safe version, or "" if unknown or unfixed.
func (v Vuln) FixedIn() string {
	if v.Unfixed || v.MaxOp != "lt" {
		return ""
	}
	return v.Max
}

// Release is the latest published version of a component.
type Release struct {
	Latest      string    `json:"latest,omitempty"`
	LastUpdated time.Time `json:"last_updated,omitzero"`
	NotFound    bool      `json:"not_found,omitempty"` // not on wordpress.org: premium, custom or removed
}

// Valid reports whether r holds a usable release; a cache entry without
// one is fetched again.
func (r *Release) Valid() bool { return r != nil }

// Advisories returns known vulnerabilities for a component. kind is plugin,
// theme, core, php, nginx or apache; key is the slug, or the version for
// core and software. stale is true when cached data past its TTL was used.
func (c *Client) Advisories(ctx context.Context, kind, key string) (rec *Record, stale bool, err error) {
	rec, info, err := c.advisories(ctx, kind, key)
	return rec, info.Stale, err
}

func (c *Client) advisories(ctx context.Context, kind, key string) (*Record, cache.Info, error) {
	rec, info, err := c.wpvulnerability(ctx, kind, key)
	if c.Wordfence == nil || kind != "plugin" && kind != "theme" && kind != "core" {
		return rec, info, err
	}
	slug := key
	if kind == "core" {
		slug = "wordpress" // core is looked up by version, the feed lists it by slug
	}
	wf, winfo, werr := c.Wordfence.Advisories(ctx, kind, slug)
	if werr != nil {
		return rec, info, err // the advisor warns once about the feed
	}
	if kind == "core" {
		// WPVulnerability answers for one version; match the feed's ranges to it.
		wf = slices.DeleteFunc(slices.Clone(wf), func(v Vuln) bool { return !v.Affects(key) })
	}
	if err != nil || rec == nil {
		// WPVulnerability failed: the feed alone still checks known
		// vulnerabilities, which is why it's there.
		return merge(&Record{Vulns: []Vuln{}}, wf), winfo, nil
	}
	return merge(rec, wf), joinInfo(info, winfo), nil
}

// joinInfo describes data built from two lookups: stale if either was,
// fetched when the older stale one was.
func joinInfo(a, b cache.Info) cache.Info {
	switch {
	case a.Stale && b.Stale && b.Fetched.Before(a.Fetched), !a.Stale && b.Stale:
		return b
	}
	return a
}

func (c *Client) wpvulnerability(ctx context.Context, kind, key string) (*Record, cache.Info, error) {
	c.init()
	return cache.Load(c.store, ctx, "wpvulnerability/"+kind, key, func(ctx context.Context) (*Record, error) {
		var raw rawResponse
		if err := c.getJSON(ctx, c.VulnBase+"/"+kind+"/"+url.PathEscape(key)+"/", &raw); err != nil {
			return nil, err
		}
		if raw.Error.on() {
			return nil, fmt.Errorf("wpvulnerability: %s", raw.Message)
		}
		var d rawData
		if len(raw.Data) > 0 && raw.Data[0] == '{' {
			if err := json.Unmarshal(raw.Data, &d); err != nil {
				return nil, fmt.Errorf("wpvulnerability: %w", err)
			}
		}
		return d.normalize(), nil
	})
}

// Latest returns the newest release of a plugin, a theme, or core (slug "wordpress").
func (c *Client) Latest(ctx context.Context, kind, slug string) (rel *Release, stale bool, err error) {
	rel, info, err := c.latest(ctx, kind, slug)
	return rel, info.Stale, err
}

func (c *Client) latest(ctx context.Context, kind, slug string) (*Release, cache.Info, error) {
	c.init()
	return cache.Load(c.store, ctx, "wordpress.org/"+kind, slug, func(ctx context.Context) (*Release, error) {
		switch kind {
		case "core":
			var v struct {
				Offers []struct {
					Current string `json:"current"`
				} `json:"offers"`
			}
			if err := c.getJSON(ctx, c.WPOrgBase+"/core/version-check/1.7/", &v); err != nil {
				return nil, err
			}
			if len(v.Offers) == 0 {
				return &Release{NotFound: true}, nil
			}
			return &Release{Latest: v.Offers[0].Current}, nil
		case "plugin", "theme":
			q := url.Values{"action": {kind + "_information"}, "slug": {slug}}
			for _, f := range []string{"sections", "versions", "reviews", "screenshots", "banners", "icons", "contributors", "description", "tags"} {
				q.Set("fields["+f+"]", "0")
			}
			var v struct {
				Error       string `json:"error"`
				Version     string `json:"version"`
				LastUpdated string `json:"last_updated"`
			}
			if err := c.getJSON(ctx, c.WPOrgBase+"/"+kind+"s/info/1.2/?"+q.Encode(), &v); err != nil {
				return nil, err
			}
			if v.Error != "" || v.Version == "" {
				return &Release{NotFound: true}, nil
			}
			return &Release{Latest: v.Version, LastUpdated: parseWPDate(v.LastUpdated)}, nil
		}
		return nil, fmt.Errorf("unknown kind %q", kind)
	})
}

// Refresh re-fetches every cached record plus the Wordfence feed when one
// is set, ignoring the TTL. It returns how many were refreshed and how
// many failed.
func (c *Client) Refresh(ctx context.Context) (ok, failed int, err error) {
	c.init()
	if c.CacheDir == "" {
		return 0, 0, errors.New("no cache directory")
	}
	// The feed is fetched whole, so it needs no earlier scan to refresh.
	if w := c.Wordfence; w != nil {
		fw := &Wordfence{HTTP: w.HTTP, UserAgent: w.UserAgent, Key: w.Key, Base: w.Base, CacheDir: w.CacheDir, TTL: w.TTL, Timeout: w.Timeout, Force: true}
		if _, _, werr := fw.index(ctx); werr != nil {
			failed++
		} else {
			ok++
		}
	}
	if _, err := os.Stat(c.CacheDir); err != nil {
		return ok, failed, err
	}
	force := &Client{
		HTTP: c.HTTP, UserAgent: c.UserAgent, CacheDir: c.CacheDir, TTL: c.TTL,
		VulnBase: c.VulnBase, WPOrgBase: c.WPOrgBase, PHPNetBase: c.PHPNetBase, Pace: c.Pace, Timeout: c.Timeout, Force: true,
	}
	err = c.store.Entries(func(kind, key string) error {
		var ferr error
		source, sub, _ := strings.Cut(kind, "/")
		switch {
		case source == "wpvulnerability" && sub != "":
			_, _, ferr = force.Advisories(ctx, sub, key)
		case source == "wordpress.org" && sub != "":
			_, _, ferr = force.Latest(ctx, sub, key)
		case kind == "php.net/releases":
			_, _, ferr = force.PHPBranches(ctx)
		default:
			return nil // osv/, wordfence/ and anything else belong to other clients
		}
		if ferr != nil {
			failed++
		} else {
			ok++
		}
		return ctx.Err()
	})
	return ok, failed, err
}

// Prefetch looks up everything a scan of a site with fingerprint fp would
// ask the data services, so the answers are cached for a later --offline
// scan (rhythm tuner update --prefetch). Fresh cached copies are kept. It
// returns the warnings such a scan would print and the data status.
func (c *Client) Prefetch(ctx context.Context, fp fingerprint.Result) (warnings []string, status string) {
	_, warnings, status = (&Advisor{Client: c}).AdviseStatus(ctx, &url.URL{}, fp)
	return warnings, status
}

// Unreachable lists the data hosts this client gave up on after a timeout
// or connection error; their lookups fall back to cached data.
func (c *Client) Unreachable() []string {
	c.init()
	return c.breaker.Down()
}

func (c *Client) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	return c.breaker.Do(ctx, req.URL.Host, func() error {
		if err := c.lim.Wait(ctx); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, c.Timeout)
		defer cancel()
		req := req.WithContext(ctx)
		req.Header.Set("User-Agent", c.UserAgent)
		req.Header.Set("Accept", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			return fmt.Errorf("%s: HTTP %d", req.URL.Host, resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		if err != nil {
			return err
		}
		if err := json.Unmarshal(body, v); err != nil {
			return fmt.Errorf("%s: unexpected response: %w", req.URL.Host, err)
		}
		return nil
	})
}

func parseWPDate(s string) time.Time {
	for _, layout := range []string{"2006-01-02 3:04pm MST", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// --- WPVulnerability wire format ---

// flex accepts a JSON string, number, bool, null or object. The API is
// inconsistent: unfixed is "0" for plugins and 0 for PHP, and kev may be
// false or an object.
type flex string

func (f *flex) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case string:
		*f = flex(x)
	case float64:
		*f = flex(strconv.FormatFloat(x, 'f', -1, 64))
	case bool:
		*f = "0"
		if x {
			*f = "1"
		}
	case nil:
		*f = ""
	default:
		*f = "1"
	}
	return nil
}

func (f flex) on() bool { return f != "" && f != "0" && f != "false" }

type rawResponse struct {
	Error   flex            `json:"error"`
	Message flex            `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// object decodes a JSON object into T, and treats [] or null as absent:
// the API sends PHP's empty array where an object has no fields.
type object[T any] struct {
	V  T
	OK bool
}

func (o *object[T]) UnmarshalJSON(b []byte) error {
	if b = bytes.TrimSpace(b); len(b) == 0 || b[0] != '{' {
		return nil
	}
	o.OK = true
	return json.Unmarshal(b, &o.V)
}

type rawData struct {
	Name          flex              `json:"name"`
	Closed        flex              `json:"closed"`
	ClosedReason  flex              `json:"closed_reason"`
	ClosedDate    flex              `json:"closed_date"`
	DateEnd       flex              `json:"date_end"`
	Vulnerability []json.RawMessage `json:"vulnerability"` // decoded one by one so a bad entry can't sink the rest
}

type rawScore struct {
	Score    flex `json:"score"`
	Severity flex `json:"severity"`
	Vector   flex `json:"vector"`
}

type rawOperator struct {
	MinVersion  flex `json:"min_version"`
	MinOperator flex `json:"min_operator"`
	MaxVersion  flex `json:"max_version"`
	MaxOperator flex `json:"max_operator"`
	Unfixed     flex `json:"unfixed"`
}

type rawImpact struct {
	CVSS  object[rawScore] `json:"cvss"`
	CVSS3 object[rawScore] `json:"cvss3"`
	KEV   flex             `json:"kev"`
}

type rawVuln struct {
	UUID        flex                `json:"uuid"`
	Name        flex                `json:"name"`
	Description flex                `json:"description"`
	Operator    object[rawOperator] `json:"operator"`
	Source      []struct {
		ID          flex `json:"id"`
		Name        flex `json:"name"`
		Link        flex `json:"link"`
		Description flex `json:"description"`
		Date        flex `json:"date"`
	} `json:"source"`
	Impact object[rawImpact] `json:"impact"`
}

var (
	onlyVersion = regexp.MustCompile(`^[0-9][0-9.]*$`)
	cveID       = regexp.MustCompile(`^CVE-\d{4}-\d+$`)
	langPrefix  = regexp.MustCompile(`^\[[a-z]{2}\]\s*`)
	// A name that only states a range, like "PHP 8.4 < 8.4.27".
	rangeName = regexp.MustCompile(`^[^<>=]*\s[<>]=?\s*[0-9][0-9.]*$`)
	// "In PHP versions 8.2.* before 8.2.31, and 8.3.* before 8.3.31, " opens
	// many PHP advisories and crowds out what the flaw is.
	versionLead = regexp.MustCompile(`(?i)^In [A-Za-z ]*?versions?\s+(?:(?:and|from)\s+)?(?:[0-9][0-9.*x]*\s+(?:before|through|prior to)\s+[0-9][0-9.]*,?\s*(?:and\s+(?:from\s+)?)?)+`)
)

var severityLetter = map[string]string{"c": "critical", "h": "high", "m": "medium", "l": "low", "n": ""}

func (d rawData) normalize() *Record {
	rec := &Record{
		Name:         clean(string(d.Name)),
		Closed:       d.Closed.on(),
		ClosedReason: string(d.ClosedReason),
		ClosedDate:   string(d.ClosedDate),
		EndOfLife:    string(d.DateEnd),
		Vulns:        []Vuln{},
	}
	for _, msg := range d.Vulnerability {
		var rv rawVuln
		if json.Unmarshal(msg, &rv) != nil {
			continue
		}
		v := Vuln{ID: string(rv.UUID)}
		for _, s := range rv.Source {
			if cveID.MatchString(string(s.ID)) {
				v.CVEs = append(v.CVEs, string(s.ID))
			}
			if s.Link != "" && len(v.References) < 5 {
				v.References = append(v.References, string(s.Link))
			}
			// Some sources repeat the bare ID as the description.
			if v.Description == "" && s.Description != "" && !cveID.MatchString(string(s.Description)) {
				v.Description = langPrefix.ReplaceAllString(string(s.Description), "")
			}
			if d := string(s.Date); d != "" && (v.Published == "" || d < v.Published) {
				v.Published = d
			}
			// Advisory names ("Contact Form 7 <= 5.3.1 - Arbitrary File Upload")
			// read better than bare IDs.
			if v.Title == "" && s.Name != "" && s.Name != s.ID {
				v.Title = clean(string(s.Name))
			}
		}
		if v.Title == "" && rv.Name != "" && !onlyVersion.MatchString(string(rv.Name)) {
			v.Title = clean(string(rv.Name))
		}
		// A bare ID or version range makes a poor title; prefer the
		// description's opening.
		if (v.Title == "" || cveID.MatchString(v.Title) || rangeName.MatchString(v.Title)) && v.Description != "" {
			v.Title = summary(v.Description)
		}
		if (v.Title == "" || rangeName.MatchString(v.Title)) && len(v.CVEs) > 0 {
			v.Title = v.CVEs[0]
		}
		if v.Description == "" && rv.Description != "" {
			v.Description = string(rv.Description)
		}
		for _, sc := range []object[rawScore]{rv.Impact.V.CVSS3, rv.Impact.V.CVSS} {
			if !sc.OK || v.Severity != "" {
				continue
			}
			sev := strings.ToLower(string(sc.V.Severity))
			if full, ok := severityLetter[sev]; ok {
				sev = full
			}
			v.Severity = sev
			v.CVSS, _ = strconv.ParseFloat(string(sc.V.Score), 64)
			v.Vector = string(sc.V.Vector)
		}
		v.KEV = rv.Impact.V.KEV.on()
		if rv.Operator.OK {
			op := rv.Operator.V
			v.Min, v.MinOp = string(op.MinVersion), string(op.MinOperator)
			v.Max, v.MaxOp = string(op.MaxVersion), string(op.MaxOperator)
			v.Unfixed = op.Unfixed.on()
		}
		rec.Vulns = append(rec.Vulns, v)
	}
	return rec
}

// clean decodes HTML entities and collapses runs of whitespace, which
// some upstream advisory titles contain.
func clean(s string) string { return strings.Join(strings.Fields(html.UnescapeString(s)), " ") }

// summary shortens a description to a title, dropping a leading list of
// affected versions.
func summary(desc string) string {
	s := clean(desc)
	if rest := versionLead.ReplaceAllString(s, ""); rest != s && rest != "" {
		r := []rune(rest)
		s = strings.ToUpper(string(r[0])) + string(r[1:])
	}
	return truncate(s, 90)
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return strings.TrimSpace(string(r[:n-1])) + "…"
	}
	return s
}
