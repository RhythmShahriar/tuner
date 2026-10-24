// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RhythmShahriar/tuner/vulns/cache"
	"github.com/RhythmShahriar/tuner/vulns/ratelimit"
)

const (
	// DefaultWordfenceBase is the Wordfence Intelligence v3 API.
	DefaultWordfenceBase = "https://www.wordfence.com/api/intelligence/v3"
	// WordfenceTimeout bounds one download of the feed, which is large.
	WordfenceTimeout = 3 * time.Minute

	// Wordfence's terms let anyone reuse a record if they link to it and
	// reproduce Defiant's copyright notice and license. Findings link to
	// each record; these are the fallbacks when the feed omits them.
	wordfenceNotice     = "Copyright Defiant Inc."
	wordfenceLicenseURL = "https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/"
	wordfenceRecordURL  = "https://www.wordfence.com/threat-intel/vulnerabilities/id/"

	// The feed is a few hundred megabytes; refuse anything absurd.
	maxWordfenceFeed = 1 << 30
)

// wordfenceFormat versions the index on disk; bump it whenever what the
// index holds changes.
const wordfenceFormat = 1

// Wordfence is the optional second vulnerability source: the Wordfence
// Intelligence production feed, which needs a free API key. It downloads
// the whole feed, keeps an index by type and slug on disk and refreshes it
// once a day. The key is only ever sent in the Authorization header and is
// never part of an error or warning.
type Wordfence struct {
	HTTP      *http.Client
	UserAgent string
	Key       string        // API key; required
	Base      string        // "" means DefaultWordfenceBase
	CacheDir  string        // "" disables the disk cache
	TTL       time.Duration // 0 means DefaultTTL
	Offline   bool          // never fetch; use the cached index however old
	Force     bool          // always fetch, ignoring the TTL (rhythm tuner update)
	Timeout   time.Duration // one feed download; 0 means WordfenceTimeout

	once    sync.Once
	http    *http.Client
	breaker ratelimit.Breaker
	store   *cache.Store

	mu              sync.Mutex
	lastErr         error
	notice, license string // from the last index loaded
}

// wordfenceIndex is the feed reduced to what Tuner matches: advisories per
// "type/slug" (plugin/akismet, theme/astra, core/wordpress), one per
// affected range.
type wordfenceIndex struct {
	Notice     string            `json:"notice,omitempty"`
	LicenseURL string            `json:"license_url,omitempty"`
	Vulns      map[string][]Vuln `json:"vulns"`
}

// Valid reports whether the index is usable; a cache entry without one is
// fetched again.
func (x *wordfenceIndex) Valid() bool { return x != nil && x.Vulns != nil }

func (w *Wordfence) init() {
	w.once.Do(func() {
		w.http = ratelimit.FastClient(w.HTTP)
		if w.Base == "" {
			w.Base = DefaultWordfenceBase
		}
		if w.TTL <= 0 {
			w.TTL = DefaultTTL
		}
		if w.Timeout <= 0 {
			w.Timeout = WordfenceTimeout
		}
		w.store = &cache.Store{Dir: w.CacheDir, TTL: w.TTL, Offline: w.Offline, Force: w.Force, Format: wordfenceFormat}
	})
}

// index returns the feed's index, from the cache when it is fresh.
func (w *Wordfence) index(ctx context.Context) (*wordfenceIndex, cache.Info, error) {
	w.init()
	x, info, err := cache.Load(w.store, ctx, "wordfence", "production", w.download)
	w.mu.Lock()
	w.lastErr = err
	if err == nil {
		w.notice, w.license = x.Notice, x.LicenseURL
	}
	w.mu.Unlock()
	return x, info, err
}

// Err is the error of the last feed lookup, or nil. Scans turn it into one
// warning instead of one per component.
func (w *Wordfence) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

// Advisories returns the feed's advisories for a plugin, theme or core
// (slug "wordpress"); every other kind has none.
func (w *Wordfence) Advisories(ctx context.Context, kind, slug string) ([]Vuln, cache.Info, error) {
	if kind != "plugin" && kind != "theme" && kind != "core" {
		return nil, cache.Info{}, nil
	}
	x, info, err := w.index(ctx)
	if err != nil {
		return nil, info, err
	}
	return x.Vulns[kind+"/"+strings.ToLower(slug)], info, nil
}

// Source credits the feed in findings, with the copyright notice and
// license its records carry.
func (w *Wordfence) Source() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return fmt.Sprintf("Wordfence Intelligence (%s; license %s)", cmpOr(w.notice, wordfenceNotice), cmpOr(w.license, wordfenceLicenseURL))
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// download fetches the production feed and indexes it as it streams in,
// so the raw feed is never held in memory at once.
func (w *Wordfence) download(ctx context.Context) (*wordfenceIndex, error) {
	if w.Key == "" {
		return nil, errors.New("wordfence: no API key")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.Base+"/vulnerabilities/production", nil)
	if err != nil {
		return nil, err
	}
	var x *wordfenceIndex
	err = w.breaker.Do(ctx, req.URL.Host, func() error {
		ctx, cancel := context.WithTimeout(ctx, w.Timeout)
		defer cancel()
		req := req.WithContext(ctx)
		req.Header.Set("User-Agent", w.UserAgent)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+w.Key)
		resp, err := w.http.Do(req)
		if err != nil {
			return w.scrub(err)
		}
		defer func() { _ = resp.Body.Close() }()
		switch resp.StatusCode {
		case http.StatusOK:
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Errorf("%s: HTTP %d; check TUNER_WORDFENCE_KEY", req.URL.Host, resp.StatusCode)
		default:
			return fmt.Errorf("%s: HTTP %d", req.URL.Host, resp.StatusCode)
		}
		x, err = indexWordfence(io.LimitReader(resp.Body, maxWordfenceFeed))
		if err != nil {
			return fmt.Errorf("%s: unexpected response: %w", req.URL.Host, w.scrub(err))
		}
		return nil
	})
	return x, err
}

// scrub keeps the API key out of an error message, whatever produced it.
func (w *Wordfence) scrub(err error) error {
	if err == nil || w.Key == "" || !strings.Contains(err.Error(), w.Key) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), w.Key, "[key]"))
}

// --- Wordfence Intelligence wire format ---

type wfRange struct {
	From          flex `json:"from_version"`
	FromInclusive bool `json:"from_inclusive"`
	To            flex `json:"to_version"`
	ToInclusive   bool `json:"to_inclusive"`
}

type wfRecord struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Software []struct {
		Type             string             `json:"type"`
		Slug             string             `json:"slug"`
		AffectedVersions map[string]wfRange `json:"affected_versions"`
		Patched          bool               `json:"patched"`
		PatchedVersions  []string           `json:"patched_versions"`
	} `json:"software"`
	Informational bool     `json:"informational"`
	Description   string   `json:"description"`
	References    []string `json:"references"`
	CVSS          struct {
		Vector string `json:"vector"`
		Score  flex   `json:"score"`
		Rating string `json:"rating"`
	} `json:"cvss"`
	CVE        string `json:"cve"`
	Published  string `json:"published"`
	Copyrights struct {
		Defiant struct {
			Notice     string `json:"notice"`
			LicenseURL string `json:"license_url"`
		} `json:"defiant"`
	} `json:"copyrights"`
}

// indexWordfence reads the feed, a JSON object of records keyed by ID, one
// record at a time. A record that doesn't decode is skipped, like a bad
// WPVulnerability entry.
func indexWordfence(r io.Reader) (*wordfenceIndex, error) {
	dec := json.NewDecoder(r)
	if t, err := dec.Token(); err != nil {
		return nil, err
	} else if t != json.Delim('{') {
		return nil, errors.New("the feed is not a JSON object")
	}
	x := &wordfenceIndex{Vulns: map[string][]Vuln{}}
	for dec.More() {
		if _, err := dec.Token(); err != nil { // the record's ID
			return nil, err
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		var rec wfRecord
		if json.Unmarshal(raw, &rec) != nil || rec.ID == "" || rec.Informational {
			continue
		}
		if x.Notice == "" {
			x.Notice, x.LicenseURL = rec.Copyrights.Defiant.Notice, rec.Copyrights.Defiant.LicenseURL
		}
		for _, sw := range rec.Software {
			if sw.Type != "plugin" && sw.Type != "theme" && sw.Type != "core" {
				continue
			}
			key := sw.Type + "/" + strings.ToLower(sw.Slug)
			for _, rg := range sw.AffectedVersions {
				x.Vulns[key] = append(x.Vulns[key], rec.vuln(rg, sw.Patched, sw.PatchedVersions))
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return x, nil
}

// vuln turns one affected range of a record into a Vuln.
func (rec *wfRecord) vuln(rg wfRange, patched bool, patchedVersions []string) Vuln {
	v := Vuln{
		ID:          rec.ID,
		Title:       clean(rec.Title),
		Description: clean(rec.Description),
		Severity:    strings.ToLower(rec.CVSS.Rating),
		Vector:      rec.CVSS.Vector,
		Sources:     []string{SourceWordfence},
		References:  []string{wordfenceRecordURL + rec.ID}, // the terms ask for a link to the record
	}
	if v.Severity == "none" {
		v.Severity = ""
	}
	v.CVSS, _ = strconv.ParseFloat(string(rec.CVSS.Score), 64)
	if cveID.MatchString(rec.CVE) {
		v.CVEs = []string{rec.CVE}
	}
	for _, ref := range rec.References {
		if len(v.References) < 5 && ref != v.References[0] {
			v.References = append(v.References, ref)
		}
	}
	v.Published, _, _ = strings.Cut(rec.Published, " ") // "2020-12-17 00:00:00"
	if from := string(rg.From); from != "" && from != "*" {
		v.Min, v.MinOp = from, "gt"
		if rg.FromInclusive {
			v.MinOp = "ge"
		}
	}
	to := string(rg.To)
	switch {
	case to == "" || to == "*":
		v.Unfixed = !patched
	case !rg.ToInclusive:
		v.Max, v.MaxOp = to, "lt"
	default:
		// "<= 5.3.1, patched in 5.3.2" reads as "< 5.3.2", which also
		// says what to update to.
		v.Max, v.MaxOp = to, "le"
		for _, p := range patchedVersions {
			if Compare(p, to) > 0 && (v.MaxOp == "le" || Compare(p, v.Max) < 0) {
				v.Max, v.MaxOp = p, "lt"
			}
		}
		v.Unfixed = !patched
	}
	return v
}
