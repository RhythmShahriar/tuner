// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package vulns matches detected WordPress core, plugins, themes, PHP and
// web server versions against known vulnerabilities.
//
// Vulnerability data comes from WPVulnerability (wpvulnerability.com),
// public domain under CC0 1.0, which aggregates CVE, Wordfence, WPScan and
// Patchstack. Latest-release data comes from the wordpress.org API, and
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
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultVulnBase   = "https://www.wpvulnerability.net"
	DefaultWPOrgBase  = "https://api.wordpress.org"
	DefaultPHPNetBase = "https://www.php.net"
	DefaultTTL        = 24 * time.Hour

	// Attribution shown with every vulnerability finding.
	Source = "WPVulnerability (wpvulnerability.com, CC0)"
)

// ErrOffline means the data isn't cached and --offline forbids fetching it.
var ErrOffline = errors.New("not cached, and offline mode is on")

// ErrOldCache means the only cached copy was written by an older Tuner,
// which normalised records differently, and --offline forbids refetching it.
var ErrOldCache = errors.New("cached by an older Tuner, and offline mode is on")

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
	VulnBase   string
	WPOrgBase  string
	PHPNetBase string

	lim  *pacer
	mu   sync.Mutex
	mem  map[string]*memo
	once sync.Once
}

type memo struct {
	once  sync.Once
	v     any
	stale bool
	err   error
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
		if c.HTTP == nil {
			c.HTTP = &http.Client{Timeout: 20 * time.Second}
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
			c.lim = &pacer{every: 200 * time.Millisecond} // be polite to free services
		case c.Pace > 0:
			c.lim = &pacer{every: c.Pace}
		}
		c.mem = map[string]*memo{}
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
	c.init()
	return load(c, ctx, "wpvulnerability/"+kind, key, func(ctx context.Context) (*Record, error) {
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
	c.init()
	return load(c, ctx, "wordpress.org/"+kind, slug, func(ctx context.Context) (*Release, error) {
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

// Refresh re-fetches every cached record, ignoring the TTL. It returns how
// many were refreshed and how many failed.
func (c *Client) Refresh(ctx context.Context) (ok, failed int, err error) {
	c.init()
	if c.CacheDir == "" {
		return 0, 0, errors.New("no cache directory")
	}
	force := &Client{
		HTTP: c.HTTP, UserAgent: c.UserAgent, CacheDir: c.CacheDir, TTL: c.TTL,
		VulnBase: c.VulnBase, WPOrgBase: c.WPOrgBase, PHPNetBase: c.PHPNetBase, Pace: c.Pace, Force: true,
	}
	err = filepath.WalkDir(c.CacheDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".json" {
			return err
		}
		rel, _ := filepath.Rel(c.CacheDir, p)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) != 3 {
			return nil
		}
		key := strings.TrimSuffix(parts[2], ".json")
		var ferr error
		switch parts[0] {
		case "wpvulnerability":
			_, _, ferr = force.Advisories(ctx, parts[1], key)
		case "wordpress.org":
			_, _, ferr = force.Latest(ctx, parts[1], key)
		case "php.net":
			_, _, ferr = force.PHPBranches(ctx)
		default:
			return nil
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

// cacheEntry is what lands on disk.
type cacheEntry[T any] struct {
	Format  int       `json:"format"`
	Fetched time.Time `json:"fetched"`
	Data    T         `json:"data"`
}

// usable reports whether e can be served: the current format, a fetch
// time and data. A truncated, hand-edited or pre-format file is not.
func (e *cacheEntry[T]) usable() bool {
	return e.Format == cacheFormat && !e.Fetched.IsZero() && validData(e.Data)
}

// validData reports whether v is worth serving: a type's own Valid method
// decides when it has one; otherwise any non-zero value (an empty, non-nil
// list included) is.
func validData(v any) bool {
	if vv, ok := v.(interface{ Valid() bool }); ok {
		return vv.Valid()
	}
	rv := reflect.ValueOf(v)
	return rv.IsValid() && !rv.IsZero()
}

// load returns fresh cached data, else fetches it, else falls back to stale
// cached data. Concurrent and repeated calls for the same key in one
// process share a single lookup.
func load[T any](c *Client, ctx context.Context, kind, key string, fetch func(context.Context) (T, error)) (T, bool, error) {
	id := kind + "/" + key
	c.mu.Lock()
	m := c.mem[id]
	if m == nil {
		m = &memo{}
		c.mem[id] = m
	}
	c.mu.Unlock()

	m.once.Do(func() {
		path := c.cachePath(kind, key)
		var cached cacheEntry[T]
		found := path != "" && readJSON(path, &cached) == nil
		have := found && cached.usable()
		age := time.Since(cached.Fetched)
		switch {
		case have && c.Offline:
			m.v, m.stale = cached.Data, age > c.TTL
			return
		case have && !c.Force && age < c.TTL:
			m.v = cached.Data
			return
		case c.Offline && found && cached.Format != cacheFormat && validData(cached.Data):
			m.err = ErrOldCache
			return
		case c.Offline:
			m.err = ErrOffline
			return
		}
		data, err := fetch(ctx)
		if err != nil {
			// A forced refresh must report failure; the cached copy stays on disk.
			if have && !c.Force {
				m.v, m.stale = cached.Data, true
				return
			}
			m.err = err
			return
		}
		m.v = data
		if path != "" {
			_ = writeJSON(path, cacheEntry[T]{Format: cacheFormat, Fetched: time.Now().UTC(), Data: data})
		}
	})
	if m.err != nil {
		var zero T
		return zero, false, m.err
	}
	return m.v.(T), m.stale, nil
}

var unsafeKey = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func (c *Client) cachePath(kind, key string) string {
	if c.CacheDir == "" || key == "" || key == "." || key == ".." {
		return ""
	}
	return filepath.Join(c.CacheDir, filepath.FromSlash(kind), unsafeKey.ReplaceAllString(key, "_")+".json")
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path) //nolint:gosec // path is built from the cache dir and a sanitized key
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// writeJSON writes atomically so a crash never leaves a torn cache file.
func writeJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (c *Client) getJSON(ctx context.Context, u string, v any) error {
	if err := c.lim.wait(ctx); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
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
}

// pacer spaces requests to third-party data services.
type pacer struct {
	mu    sync.Mutex
	every time.Duration
	next  time.Time
}

func (p *pacer) wait(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	now := time.Now()
	at := p.next
	if at.Before(now) {
		at = now
	}
	p.next = at.Add(p.every)
	p.mu.Unlock()
	t := time.NewTimer(time.Until(at))
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
