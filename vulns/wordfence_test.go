// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/vulns/cache"
)

const testKey = "wf-test-key-5f2c9a"

// fakeWordfence serves testdata/wordfence/production.json.gz the way the
// real API does, gzip-encoded, after checking the Bearer key. status, when
// set, answers every request with it instead.
type fakeWordfence struct {
	*httptest.Server
	hits   atomic.Int32
	status atomic.Int32
	mu     sync.Mutex
	auth   []string
}

func newFakeWordfence(t *testing.T) *fakeWordfence {
	t.Helper()
	feed, err := os.ReadFile("testdata/wordfence/production.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeWordfence{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.mu.Lock()
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		f.mu.Unlock()
		switch {
		case f.status.Load() != 0:
			http.Error(w, "nope", int(f.status.Load()))
		case r.URL.Path != "/api/intelligence/v3/vulnerabilities/production":
			http.NotFound(w, r)
		case r.Header.Get("Authorization") != "Bearer "+testKey:
			http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(feed)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeWordfence) client(cacheDir, key string) *Wordfence {
	return &Wordfence{HTTP: f.Client(), Base: f.URL + "/api/intelligence/v3", Key: key, CacheDir: cacheDir, UserAgent: "test"}
}

// wfFingerprint reaches every kind the feed covers.
var wfFingerprint = fingerprint.Result{
	Tech: []string{"wordpress"}, WordPress: "6.4.1",
	Components: []fingerprint.Component{
		{Type: "plugin", Slug: "contact-form-7", Version: "5.3.1"},
		{Type: "plugin", Slug: "old-gallery", Version: "1.0"},
		{Type: "plugin", Slug: "akismet", Version: "5.0"},
		{Type: "theme", Slug: "twentyten", Version: "3.0"},
	},
}

func TestWordfenceNoKeyNoRequests(t *testing.T) {
	api, wf := newFakeAPI(t), newFakeWordfence(t)
	a := newAdvisor(api, t.TempDir())
	findings, warnings := a.Advise(context.Background(), base, wfFingerprint)
	if len(findings) == 0 || len(warnings) != 0 || wf.hits.Load() != 0 {
		t.Errorf("without Wordfence: %d findings, warnings %v, %d feed requests", len(findings), warnings, wf.hits.Load())
	}
	for _, f := range findings {
		if strings.Contains(f.Source, "Wordfence") {
			t.Errorf("%s credits Wordfence: %s", f.ID, f.Source)
		}
	}
	// A client with an empty key never asks either.
	if _, _, err := wf.client(t.TempDir(), "").Advisories(context.Background(), "plugin", "akismet"); err == nil || wf.hits.Load() != 0 {
		t.Errorf("empty key: %v, %d requests", err, wf.hits.Load())
	}
}

func TestWordfenceMerged(t *testing.T) {
	api, wf := newFakeAPI(t), newFakeWordfence(t)
	cacheDir := t.TempDir()
	a := newAdvisor(api, cacheDir)
	a.Client.Wordfence = wf.client(cacheDir, testKey)
	findings, warnings := a.Advise(context.Background(), base, wfFingerprint)
	if len(warnings) != 0 {
		t.Errorf("warnings %v", warnings)
	}
	got := byID(findings)

	// The flaw both sources list is there once; the one only Wordfence
	// knows is added.
	cf7 := got["vuln-plugin-contact-form-7"]
	var cves []string
	for _, ad := range cf7.Advisories {
		cves = append(cves, ad.CVEs...)
	}
	slices.Sort(cves)
	if !slices.Equal(cves, []string{"CVE-2020-35489", "CVE-2023-6449"}) || len(cf7.Advisories) != 2 {
		t.Fatalf("cf7 advisories %+v", cf7.Advisories)
	}
	if ad := cf7.Advisories[0]; ad.CVSS != 10 || ad.ID != "u1" || !ad.KEV || ad.FixedIn != "5.3.2" ||
		!slices.Contains(ad.References, wordfenceRecordURL+"6f3b2c0e-0001-4a6e-9c1d-000000000001") {
		t.Errorf("merged advisory %+v", ad)
	}
	if ad := cf7.Advisories[1]; ad.FixedIn != "5.8.4" || ad.Severity != "high" || ad.References[0] != wordfenceRecordURL+"6f3b2c0e-0002-4a6e-9c1d-000000000002" {
		t.Errorf("Wordfence-only advisory %+v", ad)
	}
	if !strings.HasPrefix(cf7.Source, Source+"; Wordfence Intelligence (Copyright 2012-2026 Defiant Inc.; license https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/)") {
		t.Errorf("source %q", cf7.Source)
	}

	// Core: the same CVE once, and the feed's ranges matched to the version.
	if core := got["vuln-core"]; len(core.Advisories) != 1 || core.Advisories[0].CVEs[0] != "CVE-2024-31211" {
		t.Errorf("core %+v", core.Advisories)
	}
	// A closed plugin WPVulnerability has no advisories for, and a theme.
	if og := got["vuln-plugin-old-gallery"]; len(og.Advisories) != 1 || !strings.Contains(og.Fix, "No fixed version") {
		t.Errorf("old-gallery %+v", og)
	}
	if _, ok := got["wp-plugin-closed"]; !ok {
		t.Error("closed status lost in the merge")
	}
	if th := got["vuln-theme-twentyten"]; len(th.Advisories) != 1 || th.Advisories[0].FixedIn != "4.0" {
		t.Errorf("theme %+v", th)
	}
	// Informational records aren't findings.
	if _, ok := got["vuln-plugin-akismet"]; ok {
		t.Error("informational record reported")
	}

	// One download for the whole scan, with the key as a Bearer token, cached on disk.
	if wf.hits.Load() != 1 || wf.auth[0] != "Bearer "+testKey {
		t.Errorf("%d feed requests, auth %q", wf.hits.Load(), wf.auth)
	}
	store := &cache.Store{Dir: cacheDir, Format: wordfenceFormat}
	if e, ok, _ := cache.Read[*wordfenceIndex](store, "wordfence", "production"); !ok || len(e.Data.Vulns["plugin/contact-form-7"]) != 2 {
		t.Errorf("cached index: %+v", e)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "wordfence", "production.json")); err != nil {
		t.Error(err)
	}

	// Offline, from the cache: same answer, no requests.
	off := newAdvisor(api, cacheDir)
	off.Client.Offline = true
	off.Client.Wordfence = &Wordfence{Key: testKey, CacheDir: cacheDir, Offline: true}
	findings, warnings = off.Advise(context.Background(), base, wfFingerprint)
	if len(byID(findings)["vuln-plugin-contact-form-7"].Advisories) != 2 || len(warnings) != 0 || wf.hits.Load() != 1 {
		t.Errorf("offline: %v, %d requests", warnings, wf.hits.Load())
	}
	// Offline without a cached feed: one warning, WPVulnerability still used.
	off = newAdvisor(api, t.TempDir())
	off.Client.Wordfence = &Wordfence{Key: testKey, CacheDir: t.TempDir(), Offline: true}
	findings, warnings = off.Advise(context.Background(), base, wfFingerprint)
	if !slices.Contains(warnings, "Wordfence Intelligence feed not cached; run once online to cache it") || byID(findings)["vuln-plugin-contact-form-7"].ID == "" {
		t.Errorf("offline uncached: %v", warnings)
	}
}

func TestWordfenceCoversWPVulnerabilityOutage(t *testing.T) {
	api, wf := newFakeAPI(t), newFakeWordfence(t)
	api.down.Store(true)
	a := newAdvisor(api, t.TempDir())
	a.Client.Wordfence = wf.client(t.TempDir(), testKey)
	findings, _ := a.Advise(context.Background(), base, wfFingerprint)
	if cf7 := byID(findings)["vuln-plugin-contact-form-7"]; len(cf7.Advisories) != 2 {
		t.Errorf("with WPVulnerability down: %+v", cf7)
	}
}

func TestWordfenceKeyNeverInWarnings(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusInternalServerError} {
		api, wf := newFakeAPI(t), newFakeWordfence(t)
		wf.status.Store(int32(status))
		a := newAdvisor(api, t.TempDir())
		a.Client.Wordfence = wf.client(t.TempDir(), testKey)
		findings, warnings := a.Advise(context.Background(), base, wfFingerprint)
		if len(warnings) != 1 || !strings.HasPrefix(warnings[0], "couldn't fetch the Wordfence Intelligence feed") ||
			!strings.HasSuffix(warnings[0], "matched with WPVulnerability alone") || len(byID(findings)["vuln-plugin-contact-form-7"].Advisories) != 1 {
			t.Errorf("HTTP %d: warnings %v", status, warnings)
		}
		if status == http.StatusUnauthorized && !strings.Contains(warnings[0], "check TUNER_WORDFENCE_KEY") {
			t.Errorf("401 doesn't say what to check: %v", warnings)
		}
		if strings.Contains(strings.Join(warnings, " "), testKey) || wf.auth[0] != "Bearer "+testKey {
			t.Errorf("HTTP %d: key leaked or not sent: %v", status, warnings)
		}
	}
	w := &Wordfence{Key: testKey}
	if err := w.scrub(errors.New("dial https://x/?k=" + testKey + ": refused")); strings.Contains(err.Error(), testKey) {
		t.Errorf("scrub: %v", err)
	}
}

func TestWordfenceRefresh(t *testing.T) {
	api, wf := newFakeAPI(t), newFakeWordfence(t)
	cacheDir := t.TempDir()
	c := newAdvisor(api, cacheDir).Client
	c.Wordfence = wf.client(cacheDir, testKey)
	// A cold cache still downloads the feed.
	if ok, failed, _ := c.Refresh(context.Background()); ok != 1 || failed != 0 || wf.hits.Load() != 1 {
		t.Errorf("cold refresh: ok %d failed %d, %d requests", ok, failed, wf.hits.Load())
	}
	// A fresh copy is fetched again: update ignores the TTL.
	if ok, _, err := c.Refresh(context.Background()); ok != 1 || err != nil || wf.hits.Load() != 2 {
		t.Errorf("refresh: ok %d %v, %d requests", ok, err, wf.hits.Load())
	}
	wf.status.Store(http.StatusBadGateway)
	if _, failed, _ := c.Refresh(context.Background()); failed != 1 {
		t.Errorf("down: failed %d", failed)
	}
}

func TestIndexWordfenceRanges(t *testing.T) {
	r := strings.NewReader(`{"a":{"id":"a","title":"T","software":[{"type":"plugin","slug":"P","patched":true,"patched_versions":["2.1","2.0.1"],
		"affected_versions":{"1.0 - 2.0":{"from_version":"1.0","from_inclusive":false,"to_version":"2.0","to_inclusive":true}}},
		{"type":"plugin","slug":"q","patched":false,"affected_versions":{"*":{"from_version":"*","from_inclusive":true,"to_version":"*","to_inclusive":true}}}],
		"cvss":{"score":"5.3","rating":"Medium"},"cve":"CVE-2026-1","published":"2026-01-02 03:04:05"},
		"b":["not","a","record"]}`)
	x, err := indexWordfence(r)
	if err != nil {
		t.Fatal(err)
	}
	p := x.Vulns["plugin/p"]
	if len(p) != 1 || p[0].MinOp != "gt" || p[0].Min != "1.0" || p[0].Max != "2.0.1" || p[0].MaxOp != "lt" ||
		p[0].CVSS != 5.3 || p[0].Severity != "medium" || p[0].Published != "2026-01-02" || p[0].FixedIn() != "2.0.1" {
		t.Errorf("plugin/p %+v", p)
	}
	if q := x.Vulns["plugin/q"]; len(q) != 1 || !q[0].Unfixed || !q[0].Affects("99") {
		t.Errorf("plugin/q %+v", q)
	}
	if _, err := indexWordfence(strings.NewReader(`["no"]`)); err == nil {
		t.Error("an array parsed as a feed")
	}
	if _, err := indexWordfence(strings.NewReader(`{"a":{"id":"a"`)); err == nil {
		t.Error("a truncated feed parsed")
	}
}
