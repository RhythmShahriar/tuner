// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/vulns/cache"
)

// hangingAPI accepts requests and never answers, like a data service
// behind a firewall that lets the connection through.
func hangingAPI(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	return srv, &hits
}

func plugins(prefix string, n int) fingerprint.Result {
	fp := fingerprint.Result{Tech: []string{"wordpress"}}
	for i := range n {
		fp.Components = append(fp.Components, fingerprint.Component{Type: "plugin", Slug: fmt.Sprintf("%s-%d", prefix, i), Version: "1.0"})
	}
	return fp
}

func TestUnreachableFailsFast(t *testing.T) {
	srv, hits := hangingAPI(t)
	dir := t.TempDir()
	// Five plugins with a three-day-old cache, for the second target.
	warm := plugins("warm", 5)
	for _, c := range warm.Components {
		e := cache.Entry[*Record]{Format: cacheFormat, Key: c.Slug, Fetched: time.Now().Add(-73 * time.Hour),
			Data: &Record{Vulns: []Vuln{{ID: c.Slug, Title: "Old flaw", Max: "2.0", MaxOp: "lt"}}}}
		if err := cache.WriteJSON(filepath.Join(dir, "wpvulnerability", "plugin", c.Slug+".json"), e); err != nil {
			t.Fatal(err)
		}
	}
	c := &Client{CacheDir: dir, Timeout: 2 * time.Second, VulnBase: srv.URL, WPOrgBase: srv.URL, PHPNetBase: srv.URL}
	a := &Advisor{Client: c}
	ctx := context.Background()

	// Cold: one request times out, the other lookups don't wait for theirs.
	start := time.Now()
	fs, warnings, status := a.AdviseStatus(ctx, base, plugins("cold", 5))
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("cold run took %s", d)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("%d requests reached the hanging API, want 1", n)
	}
	want := "vulnerability data unreachable, no cached data; known vulnerabilities not checked"
	if len(fs) != 0 || status != StatusMissing || len(warnings) != 1 || warnings[0] != want {
		t.Errorf("cold: %d findings, status %q, warnings %q", len(fs), status, warnings)
	}
	if got := c.Unreachable(); len(got) != 1 {
		t.Errorf("Unreachable() = %v", got)
	}

	// Warm, later in the same run: stale copies at once, one warning.
	start = time.Now()
	fs, warnings, status = a.AdviseStatus(ctx, base, warm)
	if d := time.Since(start); d > time.Second {
		t.Errorf("warm run took %s", d)
	}
	want = "vulnerability data unreachable, using cache from 3 days ago (use --offline to skip)"
	if len(fs) != 5 || status != StatusPartial || len(warnings) != 1 || warnings[0] != want {
		t.Errorf("warm: %d findings, status %q, warnings %q", len(fs), status, warnings)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("%d requests after the host went down", n)
	}
}

func TestUnreachableWarning(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		what                 string
		failed, total, stale int
		oldest               time.Time
		want                 string
	}{
		{"", 3, 3, 0, time.Time{}, "vulnerability data unreachable, no cached data; known vulnerabilities not checked"},
		{"", 0, 3, 3, now.Add(-72 * time.Hour), "vulnerability data unreachable, using cache from 3 days ago (use --offline to skip)"},
		{"", 1, 4, 0, time.Time{}, "vulnerability data unreachable, no cached data for 1 of 4 lookups; their known vulnerabilities not checked"},
		{"Composer ", 2, 5, 3, now.Add(-5 * time.Hour), "Composer vulnerability data unreachable, using cache from 5 hours ago; no cached data for 2 of 5, so their known vulnerabilities were not checked (use --offline to skip)"},
		{"", 0, 1, 1, now.Add(-30 * time.Second), "vulnerability data unreachable, using cache from 1 minute ago (use --offline to skip)"},
		{"", 0, 1, 1, time.Time{}, "vulnerability data unreachable, using cached data (use --offline to skip)"},
	} {
		if got := UnreachableWarning(c.what, c.failed, c.total, c.stale, c.oldest, now); got != c.want {
			t.Errorf("got  %q\nwant %q", got, c.want)
		}
	}
}

// A data service that answers with errors is up: no breaker, and the
// usual warning.
func TestHTTPErrorIsNotUnreachable(t *testing.T) {
	f := newFakeAPI(t)
	f.down.Store(true)
	a := newAdvisor(f, t.TempDir())
	_, warnings, _ := a.AdviseStatus(context.Background(), base, plugins("p", 3))
	if len(a.Client.Unreachable()) != 0 || len(warnings) != 1 || !strings.HasPrefix(warnings[0], "couldn't fetch vulnerability data for 3 components") {
		t.Errorf("unreachable %v, warnings %v", a.Client.Unreachable(), warnings)
	}
	if f.hits.Load() < 3 {
		t.Errorf("only %d requests: a 502 must not stop later lookups", f.hits.Load())
	}
}
