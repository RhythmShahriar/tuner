// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package osv matches Composer packages against OSV.dev (the GitHub
// Advisory Database and FriendsOfPHP's security advisories). Local scans
// use it for composer.lock; remote scans use ComposerAdvisor on a
// composer.lock the site exposes.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/RhythmShahriar/tuner/vulns"
	"github.com/RhythmShahriar/tuner/vulns/cache"
	"github.com/RhythmShahriar/tuner/vulns/ratelimit"
)

const (
	// DefaultBase is the OSV.dev API.
	DefaultBase = "https://api.osv.dev"
	// Source credits the data in reports.
	Source = "OSV.dev (GitHub Advisory Database, FriendsOfPHP)"
)

// Client queries OSV.dev for known vulnerabilities in Composer packages.
// Like vulns.Client, it caches answers on disk, refreshes them once they're
// a day old and falls back to stale copies when the service is down.
type Client struct {
	HTTP      *http.Client
	UserAgent string
	Base      string        // default DefaultBase
	CacheDir  string        // "" disables the disk cache
	TTL       time.Duration // 0 means 24h
	Offline   bool          // never fetch; use cached data however old
	Timeout   time.Duration // per request, reading the answer included; 0 means vulns.DefaultTimeout

	once    sync.Once
	http    *http.Client
	breaker ratelimit.Breaker
	store   *cache.Store
}

// Package is a Composer package at an installed version.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Vuln is the part of an OSV record Tuner uses.
type Vuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

var errOffline = errors.New("offline and not cached")

func (o *Client) init() {
	o.once.Do(func() {
		o.http = ratelimit.FastClient(o.HTTP) // see vulns.Client: fail fast when firewalled
		if o.Timeout <= 0 {
			o.Timeout = vulns.DefaultTimeout
		}
		if o.Base == "" {
			o.Base = DefaultBase
		}
		if o.TTL <= 0 {
			o.TTL = 24 * time.Hour
		}
		o.store = &cache.Store{Dir: o.CacheDir, TTL: o.TTL, Offline: o.Offline, Format: cacheFormat}
	})
}

// Result is what one Check found.
type Result struct {
	Vulns  map[Package][]Vuln // known vulnerabilities, for packages that have any
	Total  int                // packages looked up
	Failed int                // packages that couldn't be checked
	Stale  int                // packages answered from a cache past its TTL
	Err    error              // the first error, explaining Failed

	// Unreachable is set when OSV.dev timed out or refused the connection.
	// Oldest is when the oldest stale copy used instead was fetched.
	Unreachable bool
	Oldest      time.Time
}

// Status is the vulnerability data status, one of vulns.StatusOK,
// StatusPartial or StatusMissing.
func (r Result) Status() string { return vulns.DataStatus(r.Total, r.Failed, r.Stale) }

// Warning is the one warning a scan prints about r, or "" when every
// package was checked.
func (o *Client) Warning(r Result) string {
	switch {
	case r.Unreachable && (r.Failed > 0 || r.Stale > 0):
		return vulns.UnreachableWarning("Composer ", r.Failed, r.Total, r.Stale, r.Oldest, time.Now())
	case r.Failed > 0 && o.Offline:
		return fmt.Sprintf("vulnerability data not cached for %d Composer packages; run once online to cache it", r.Failed)
	case r.Failed > 0:
		return fmt.Sprintf("couldn't fetch vulnerability data for %d Composer packages (%v)", r.Failed, r.Err)
	}
	return ""
}

// older keeps the earlier of two fetch times, ignoring zero ones.
func older(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

// Query returns the known vulnerabilities for each package that has any
// and how many packages couldn't be checked (the first error explains
// why).
func (o *Client) Query(ctx context.Context, pkgs []Package) (map[Package][]Vuln, int, error) {
	r := o.Check(ctx, pkgs)
	return r.Vulns, r.Failed, r.Err
}

// Check looks pkgs up like Query and also says how complete the answer is.
func (o *Client) Check(ctx context.Context, pkgs []Package) Result {
	o.init()

	// Vulnerability IDs per package: cache first, then one batch query.
	ids := make(map[Package][]string, len(pkgs))
	stale := map[Package]cache.Entry[[]string]{}
	staleUsed := map[Package]bool{}
	res := Result{Vulns: map[Package][]Vuln{}, Total: len(pkgs)}
	var missing []Package
	for _, p := range pkgs {
		e, ok, _ := cache.Read[[]string](o.store, "packagist", packageKey(p))
		switch {
		case ok && o.Offline:
			ids[p] = e.Data
			if staleUsed[p] = time.Since(e.Fetched) > o.TTL; staleUsed[p] {
				res.Oldest = older(res.Oldest, e.Fetched)
			}
		case ok && time.Since(e.Fetched) < o.TTL:
			ids[p] = e.Data
		case ok:
			stale[p] = e
			missing = append(missing, p)
		default:
			missing = append(missing, p)
		}
	}
	failedPkg := map[Package]bool{}
	if len(missing) > 0 {
		got, err := o.batch(ctx, missing)
		for _, p := range missing {
			switch v, ok := got[p]; {
			case ok:
				ids[p] = v
				_ = cache.Write(o.store, "packagist", packageKey(p), v)
			case stale[p].Data != nil:
				ids[p] = stale[p].Data
				staleUsed[p] = true
				res.Oldest = older(res.Oldest, stale[p].Fetched)
			default:
				failedPkg[p] = true
			}
		}
		if err != nil {
			res.Err = err
		}
	}

	// Details per vulnerability, a few at a time.
	var mu sync.Mutex
	details := map[string]*Vuln{}
	staleIDs := map[string]bool{}
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, list := range ids {
		for _, id := range list {
			mu.Lock()
			_, seen := details[id]
			details[id] = nil
			mu.Unlock()
			if seen {
				continue
			}
			wg.Go(func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				v, staleAt, err := o.vuln(ctx, id, false)
				mu.Lock()
				defer mu.Unlock()
				details[id] = v
				staleIDs[id] = !staleAt.IsZero()
				res.Oldest = older(res.Oldest, staleAt)
				if err != nil && res.Err == nil {
					res.Err = err
				}
			})
		}
	}
	wg.Wait()

	for p, list := range ids {
		for _, id := range list {
			if v := details[id]; v != nil {
				res.Vulns[p] = append(res.Vulns[p], *v)
				staleUsed[p] = staleUsed[p] || staleIDs[id]
			} else {
				failedPkg[p] = true // incomplete
			}
		}
	}
	res.Failed = len(failedPkg)
	res.Unreachable = len(o.breaker.Down()) > 0
	for p, s := range staleUsed {
		if s && !failedPkg[p] {
			res.Stale++
		}
	}
	return res
}

// Refresh re-fetches every cached package and the details of every
// vulnerability they list, ignoring the TTL (rhythm-tuner update). It
// returns how many records were refreshed and how many failed; failed
// ones keep their cached copy.
func (o *Client) Refresh(ctx context.Context) (ok, failed int, err error) {
	o.init()
	if o.CacheDir == "" {
		return 0, 0, errors.New("no cache directory")
	}
	if o.Offline {
		return 0, 0, errOffline
	}
	var pkgs []Package
	seen := map[Package]bool{}
	ids := map[string]bool{}
	err = o.store.Entries(func(kind, key string) error {
		switch kind {
		case "packagist":
			if p, ok := parsePackageKey(key); ok && !seen[p] {
				seen[p] = true
				pkgs = append(pkgs, p)
			}
		case "vulns":
			ids[key] = true
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}

	if len(pkgs) > 0 {
		got, berr := o.batch(ctx, pkgs)
		for _, p := range pkgs {
			v, answered := got[p]
			if !answered {
				failed++
				continue
			}
			ok++
			_ = cache.Write(o.store, "packagist", packageKey(p), v)
			for _, id := range v {
				ids[id] = true
			}
		}
		if berr != nil && ctx.Err() != nil {
			return ok, failed, ctx.Err()
		}
	}
	for id := range ids {
		if _, _, verr := o.vuln(ctx, id, true); verr != nil {
			failed++
		} else {
			ok++
		}
		if ctx.Err() != nil {
			return ok, failed, ctx.Err()
		}
	}
	return ok, failed, nil
}

// packageKey is how a package is named in the cache.
func packageKey(p Package) string { return p.Name + "@" + p.Version }

// parsePackageKey reverses packageKey. It also takes the file name of an
// entry from before keys were stored, where "/" became "~" (or "_" in
// some development builds): Composer names are vendor/package, so the
// first "~", else the first "_", is the separator.
func parsePackageKey(key string) (Package, bool) {
	i := strings.LastIndex(key, "@")
	if i <= 0 || i == len(key)-1 {
		return Package{}, false
	}
	name := key[:i]
	switch {
	case strings.Contains(name, "/"):
	case strings.Contains(name, "~"):
		name = strings.Replace(name, "~", "/", 1)
	default:
		name = strings.Replace(name, "_", "/", 1)
	}
	return Package{Name: name, Version: key[i+1:]}, true
}

// batch asks OSV which vulnerability IDs affect each package.
func (o *Client) batch(ctx context.Context, pkgs []Package) (map[Package][]string, error) {
	if o.Offline {
		return nil, errOffline
	}
	out := map[Package][]string{}
	for start := 0; start < len(pkgs); start += 1000 {
		chunk := pkgs[start:min(start+1000, len(pkgs))]
		type query struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Version string `json:"version"`
		}
		var req struct {
			Queries []query `json:"queries"`
		}
		for _, p := range chunk {
			var q query
			q.Package.Name, q.Package.Ecosystem, q.Version = p.Name, "Packagist", p.Version
			req.Queries = append(req.Queries, q)
		}
		var resp struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := o.do(ctx, http.MethodPost, o.Base+"/v1/querybatch", req, &resp); err != nil {
			return out, err
		}
		if len(resp.Results) != len(chunk) {
			return out, fmt.Errorf("osv: %d results for %d queries", len(resp.Results), len(chunk))
		}
		for i, r := range resp.Results {
			ids := []string{}
			for _, v := range r.Vulns {
				ids = append(ids, v.ID)
			}
			out[chunk[i]] = ids
		}
	}
	return out, nil
}

// vuln returns one vulnerability's details and, when they came from a
// cache past its TTL, when that copy was fetched. force ignores the TTL
// and reports a failed fetch instead of falling back to the cached copy.
func (o *Client) vuln(ctx context.Context, id string, force bool) (*Vuln, time.Time, error) {
	e, ok, _ := cache.Read[*Vuln](o.store, "vulns", id)
	stale := ok && time.Since(e.Fetched) > o.TTL
	var staleAt time.Time
	if stale {
		staleAt = e.Fetched
	}
	if ok && !force && (o.Offline || !stale) {
		return e.Data, staleAt, nil
	}
	if o.Offline {
		return nil, time.Time{}, errOffline
	}
	var v Vuln
	if err := o.do(ctx, http.MethodGet, o.Base+"/v1/vulns/"+url.PathEscape(id), nil, &v); err != nil {
		if ok && !force {
			return e.Data, e.Fetched, nil // stale beats nothing
		}
		return nil, time.Time{}, err
	}
	_ = cache.Write(o.store, "vulns", id, &v)
	return &v, time.Time{}, nil
}

func (o *Client) do(ctx context.Context, method, u string, body, v any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", o.UserAgent)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return o.breaker.Do(ctx, req.URL.Host, func() error {
		ctx, cancel := context.WithTimeout(ctx, o.Timeout)
		defer cancel()
		resp, err := o.http.Do(req.WithContext(ctx))
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: HTTP %d", req.URL.Host, resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, v); err != nil {
			return fmt.Errorf("%s: unexpected response: %w", req.URL.Host, err)
		}
		return nil
	})
}

// cacheFormat versions the entries on disk; bump it whenever what an
// entry holds changes, so older entries are fetched again.
const cacheFormat = 1
