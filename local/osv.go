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
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
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

	once sync.Once
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

// Query returns the known vulnerabilities for each package that has any,
// and how many packages couldn't be checked (the first error explains
// why).
func (o *OSV) Query(ctx context.Context, pkgs []Package) (map[Package][]OSVVuln, int, error) {
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
	})

	// Vulnerability IDs per package: cache first, then one batch query.
	ids := make(map[Package][]string, len(pkgs))
	stale := map[Package][]string{}
	var missing []Package
	for _, p := range pkgs {
		var e cached[[]string]
		ok := readCache(o.path("packagist", p.Name+"@"+p.Version), &e)
		switch {
		case ok && (o.Offline || time.Since(e.Fetched) < o.TTL):
			ids[p] = e.Data
		case ok:
			stale[p] = e.Data
			missing = append(missing, p)
		default:
			missing = append(missing, p)
		}
	}
	failed := 0
	var firstErr error
	if len(missing) > 0 {
		got, err := o.batch(ctx, missing)
		for _, p := range missing {
			switch v, ok := got[p]; {
			case ok:
				ids[p] = v
				writeCache(o.path("packagist", p.Name+"@"+p.Version), newCached(v))
			case stale[p] != nil:
				ids[p] = stale[p]
			default:
				failed++
			}
		}
		if err != nil {
			firstErr = err
		}
	}

	// Details per vulnerability, a few at a time.
	var mu sync.Mutex
	details := map[string]*OSVVuln{}
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
				v, err := o.vuln(ctx, id)
				mu.Lock()
				defer mu.Unlock()
				details[id] = v
				if err != nil && firstErr == nil {
					firstErr = err
				}
			})
		}
	}
	wg.Wait()

	out := map[Package][]OSVVuln{}
	for p, list := range ids {
		incomplete := false
		for _, id := range list {
			if v := details[id]; v != nil {
				out[p] = append(out[p], *v)
			} else {
				incomplete = true
			}
		}
		if incomplete {
			failed++
		}
	}
	return out, failed, firstErr
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

// vuln returns one vulnerability's details.
func (o *OSV) vuln(ctx context.Context, id string) (*OSVVuln, error) {
	path := o.path("vulns", id)
	var e cached[*OSVVuln]
	ok := readCache(path, &e)
	if ok && (o.Offline || time.Since(e.Fetched) < o.TTL) {
		return e.Data, nil
	}
	if o.Offline {
		return nil, errOffline
	}
	var v OSVVuln
	if err := o.do(ctx, http.MethodGet, o.Base+"/v1/vulns/"+url.PathEscape(id), nil, &v); err != nil {
		if ok {
			return e.Data, nil // stale beats nothing
		}
		return nil, err
	}
	writeCache(path, newCached(&v))
	return &v, nil
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

// --- cache ---

// osvCacheFormat versions the entries on disk; bump it whenever what an
// entry holds changes, so older entries are fetched again.
const osvCacheFormat = 1

type cached[T any] struct {
	Format  int       `json:"format"`
	Fetched time.Time `json:"fetched"`
	Data    T         `json:"data"`
}

// newCached wraps data fetched now.
func newCached[T any](data T) cached[T] {
	return cached[T]{Format: osvCacheFormat, Fetched: time.Now().UTC(), Data: data}
}

// usable reports whether e can be served: the current format, a fetch
// time and data (an empty, non-nil ID list included).
func (e *cached[T]) usable() bool {
	rv := reflect.ValueOf(e.Data)
	return e.Format == osvCacheFormat && !e.Fetched.IsZero() && rv.IsValid() && !rv.IsZero()
}

var unsafeKey = regexp.MustCompile(`[^A-Za-z0-9._@-]`)

func (o *OSV) path(kind, key string) string {
	if o.CacheDir == "" {
		return ""
	}
	key = unsafeKey.ReplaceAllString(strings.ReplaceAll(key, "/", "~"), "_")
	if key == "" || key == "." || key == ".." {
		return ""
	}
	return filepath.Join(o.CacheDir, kind, key+".json")
}

// readCache decodes the entry at path, reporting false for a missing,
// corrupt, old-format or empty entry.
func readCache[T any](path string, e *cached[T]) bool {
	if path == "" {
		return false
	}
	b, err := os.ReadFile(path) //nolint:gosec // path is built from the cache dir and a sanitized key
	return err == nil && json.Unmarshal(b, e) == nil && e.usable()
}

// writeCache writes atomically so a crash never leaves a torn file. A
// cache that can't be written is not an error.
func writeCache(path string, v any) {
	if path == "" {
		return
	}
	b, err := json.Marshal(v)
	if err != nil || os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), path) != nil {
		_ = os.Remove(tmp.Name())
	}
}
