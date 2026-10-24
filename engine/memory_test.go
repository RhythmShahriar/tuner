// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/RhythmShahriar/tuner/checks"
)

// A site that answers every path with a 1 MiB page used to keep every
// body in the scan cache until the end: over 100 MB for one target.
func TestCacheDropsBodiesAfterLastReader(t *testing.T) {
	page := `<link href="/wp-content/plugins/akismet/a.css?ver=1.0">` + strings.Repeat("catch-all filler line\n", maxBody/20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(page))
	}))
	defer srv.Close()
	all, err := LoadChecks(checks.FS)
	if err != nil {
		t.Fatal(err)
	}
	sel, err := Select(all, Selector{})
	if err != nil {
		t.Fatal(err)
	}

	// Measure inside the last progress callback: the session and its
	// cache are still live there, unlike after Scan returns.
	var inuse atomic.Uint64
	var jobs atomic.Int64
	h := Hooks{Progress: func(done, total int) {
		jobs.Store(int64(total))
		if done == total {
			runtime.GC()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			inuse.Store(m.HeapInuse)
		}
	}}
	if _, err := New(sel, Options{HTTPClient: srv.Client()}).Scan(context.Background(), srv.URL, h); err != nil {
		t.Fatal(err)
	}
	if jobs.Load() < 40 {
		t.Fatalf("only %d check requests; the test needs the default profile's", jobs.Load())
	}
	t.Logf("HeapInuse at scan end: %d MiB after %d check requests", inuse.Load()>>20, jobs.Load())
	if got := inuse.Load(); got == 0 || got >= 32<<20 {
		t.Errorf("HeapInuse at scan end = %d MiB after %d check requests, want under 32 MiB", got>>20, jobs.Load())
	}
}

// Checks that read the same path, and the soft-404 probe for it, all see
// the full body however the jobs interleave.
func TestCacheSharedPathKeepsBodyForEveryReader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Write([]byte("APP_KEY=one\nDB_PASSWORD=two\nMAIL_HOST=three\n"))
			return
		}
		w.Write([]byte("<html>not here</html>"))
	}))
	defer srv.Close()
	var cs []*Check
	for _, key := range []string{"APP_KEY", "DB_PASSWORD", "MAIL_HOST", "APP_KEY=one", "DB_PASSWORD=two"} {
		cs = append(cs, mustParse(t, `
id: t-`+strings.ToLower(strings.ReplaceAll(key, "=", "-"))+`
name: shared
severity: low
request: {path: ["/.env", "/other"]}
match: {all: [{status: 200}, {regex: "(?m)^`+key+`"}, {not_baseline: true}]}
`))
	}
	for range 20 {
		res, err := New(cs, Options{Concurrency: 8, HTTPClient: srv.Client()}).Scan(context.Background(), srv.URL, Hooks{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != len(cs) {
			t.Fatalf("%d findings, want %d: %+v", len(res.Findings), len(cs), res.Findings)
		}
		if res.Requests != 5 {
			t.Fatalf("%d requests, want 5 (home, soft-404 probe, two paths, the .env probe): a dropped body was fetched again", res.Requests)
		}
	}
}
