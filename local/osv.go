// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

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
)

const (
	DefaultOSVBase = "https://api.osv.dev"
	// OSVSource credits the data in reports.
	OSVSource = "OSV.dev (GitHub Advisory Database, FriendsOfPHP)"
)

// OSV queries OSV.dev for known vulnerabilities in Composer packages. Like
// vulns.Client, it caches answers on disk, refreshes them once they're a
// day old, and falls back to stale copies when the service is down.
type OSV struct {
	HTTP      *http.Client
	UserAgent string
	Base      string        // default DefaultOSVBase
	CacheDir  string        // "" disables the disk cache
	TTL       time.Duration // 0 means 24h
	Offline   bool          // never fetch; use cached data however old

	once  sync.Once
	store *cache.Store
}

// Package is a Composer package at an installed version.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// OSVVuln is the part of an OSV record Tuner uses.
type OSVVuln struct {
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

func (o *OSV) init() {
	o.once.Do(func() {
		if o.HTTP == nil {
			o.HTTP = &http.Client{Timeout: 20 * time.Second}
		}
		if o.Base == "" {
			o.Base = DefaultOSVBase
		}
		if o.TTL <= 0 {
			o.TTL = 24 * time.Hour
		}
		o.store = &cache.Store{Dir: o.CacheDir, TTL: o.TTL, Offline: o.Offline, Format: osvCacheFormat}
	})
}

// OSVResult is what one Check found.
type OSVResult struct {
	Vulns  map[Package][]OSVVuln // known vulnerabilities, for packages that have any
	Total  int                   // packages looked up
	Failed int                   // packages that couldn't be checked
	Stale  int                   // packages answered from a cache past its TTL
	Err    error                 // the first error, explaining Failed
}

// Status is the vulnerability data status, one of vulns.StatusOK,
// StatusPartial or StatusMissing.
func (r OSVResult) Status() string { return vulns.DataStatus(r.Total, r.Failed, r.Stale) }

// Query returns the known vulnerabilities for each package that has any,
// and how many packages couldn't be checked (the first error explains
// why).
func (o *OSV) Query(ctx context.Context, pkgs []Package) (map[Package][]OSVVuln, int, error) {
	r := o.Check(ctx, pkgs)
	return r.Vulns, r.Failed, r.Err
}

// Check looks pkgs up like Query and also says how complete the answer is.
func (o *OSV) Check(ctx context.Context, pkgs []Package) OSVResult {
	o.init()

	// Vulnerability IDs per package: cache first, then one batch query.
	ids := make(map[Package][]string, len(pkgs))
	stale := map[Package][]string{}
	staleUsed := map[Package]bool{}
	var missing []Package
	for _, p := range pkgs {
		e, ok, _ := cache.Read[[]string](o.store, "packagist", packageKey(p))
		switch {
		case ok && o.Offline:
			ids[p] = e.Data
			staleUsed[p] = time.Since(e.Fetched) > o.TTL
		case ok && time.Since(e.Fetched) < o.TTL:
			ids[p] = e.Data
		case ok:
			stale[p] = e.Data
			missing = append(missing, p)
		default:
			missing = append(missing, p)
		}
	}
	res := OSVResult{Vulns: map[Package][]OSVVuln{}, Total: len(pkgs)}
	failedPkg := map[Package]bool{}
	if len(missing) > 0 {
		got, err := o.batch(ctx, missing)
		for _, p := range missing {
			switch v, ok := got[p]; {
			case ok:
				ids[p] = v
				_ = cache.Write(o.store, "packagist", packageKey(p), v)
			case stale[p] != nil:
				ids[p] = stale[p]
				staleUsed[p] = true
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
	details := map[string]*OSVVuln{}
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
				v, wasStale, err := o.vuln(ctx, id, false)
				mu.Lock()
				defer mu.Unlock()
				details[id] = v
				staleIDs[id] = wasStale
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
func (o *OSV) Refresh(ctx context.Context) (ok, failed int, err error) {
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
// entry from before keys were stored, where "/" became "_": Composer
// names are vendor/package, so the first "_" is the best guess.
func parsePackageKey(key string) (Package, bool) {
	i := strings.LastIndex(key, "@")
	if i <= 0 || i == len(key)-1 {
		return Package{}, false
	}
	name := key[:i]
	if !strings.Contains(name, "/") {
		name = strings.Replace(name, "_", "/", 1)
	}
	return Package{Name: name, Version: key[i+1:]}, true
}

// batch asks OSV which vulnerability IDs affect each package.
func (o *OSV) batch(ctx context.Context, pkgs []Package) (map[Package][]string, error) {
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

// vuln returns one vulnerability's details, and whether they came from
// a cache past its TTL. force ignores the TTL and reports a failed fetch
// instead of falling back to the cached copy.
func (o *OSV) vuln(ctx context.Context, id string, force bool) (*OSVVuln, bool, error) {
	e, ok, _ := cache.Read[*OSVVuln](o.store, "vulns", id)
	stale := ok && time.Since(e.Fetched) > o.TTL
	if ok && !force && (o.Offline || !stale) {
		return e.Data, stale, nil
	}
	if o.Offline {
		return nil, false, errOffline
	}
	var v OSVVuln
	if err := o.do(ctx, http.MethodGet, o.Base+"/v1/vulns/"+url.PathEscape(id), nil, &v); err != nil {
		if ok && !force {
			return e.Data, true, nil // stale beats nothing
		}
		return nil, false, err
	}
	_ = cache.Write(o.store, "vulns", id, &v)
	return &v, false, nil
}

func (o *OSV) do(ctx context.Context, method, u string, body, v any) error {
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
	resp, err := o.HTTP.Do(req)
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
}

// osvCacheFormat versions the entries on disk; bump it whenever what an
// entry holds changes, so older entries are fetched again.
const osvCacheFormat = 1
