// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/vulns"
	"github.com/RhythmShahriar/tuner/vulns/osv/osvtest"
)

const lockFile = `{
	"packages": [
		{"name": "laravel/framework", "version": "v8.0.0"},
		{"name": "monolog/monolog", "version": "2.9.1"},
		{"name": "acme/abandoned", "version": "1.0.0"},
		{"name": "acme/branch", "version": "dev-main"}
	],
	"packages-dev": [{"name": "phpunit/phpunit", "version": "9.6.0"}]
}`

func TestComposer(t *testing.T) {
	api := osvtest.NewServer(t)
	cacheDir := t.TempDir()
	root := tree(t, map[string]string{"composer.lock": lockFile, "index.php": "<?php"})
	osv := func(offline bool) *OSV {
		return &OSV{HTTP: api.Client(), Base: api.URL, CacheDir: cacheDir, Offline: offline, UserAgent: "test"}
	}

	res := scanTree(t, root, Options{OSV: osv(false)})
	if got := ids(res); !slices.Equal(got, []string{"vuln-composer-laravel-framework /composer.lock", "vuln-composer-acme-abandoned /composer.lock"}) {
		t.Fatalf("findings %v, warnings %v", got, res.Warnings)
	}
	f := find(res, "vuln-composer-laravel-framework")
	if f.Severity != engine.High || f.Title != "laravel/framework 8.0.0: 2 known vulnerabilities" || f.Source != OSVSource ||
		len(f.Advisories) != 2 || f.Advisories[0].ID != "GHSA-aaaa" || f.Advisories[0].FixedIn != "8.22.1" ||
		!slices.Equal(f.Advisories[0].CVEs, []string{"CVE-2021-21263"}) || f.Advisories[0].Title != "Query binding exploitation" ||
		!slices.Contains(f.Tags, "laravel") || !strings.Contains(f.Fix, "8.40.0 or later") {
		t.Errorf("laravel finding: %+v", f)
	}
	if f := find(res, "vuln-composer-acme-abandoned"); f.Severity != engine.Medium || !strings.Contains(f.Fix, "No fixed version") {
		t.Errorf("unfixed finding: %+v", f)
	}
	if !res.Fingerprint.Has("laravel") {
		t.Error("laravel/framework in composer.lock should mark the site Laravel")
	}

	// Cached: offline with the API down gives the same answer, with no requests.
	api.Down.Store(true)
	hits := api.Hits.Load()
	res = scanTree(t, root, Options{OSV: osv(true)})
	if len(res.Findings) != 2 || len(res.Warnings) != 0 || api.Hits.Load() != hits {
		t.Errorf("offline: %v %v, %d requests", ids(res), res.Warnings, api.Hits.Load()-hits)
	}

	// Nothing cached and the API down: a warning, not an error.
	res = scanTree(t, root, Options{OSV: &OSV{HTTP: api.Client(), Base: api.URL, CacheDir: t.TempDir()}})
	if len(res.Findings) != 0 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "4 Composer packages") {
		t.Errorf("down: %v %v", ids(res), res.Warnings)
	}
	res = scanTree(t, root, Options{OSV: &OSV{CacheDir: t.TempDir(), Offline: true}})
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "run once online") {
		t.Errorf("offline, uncached: %v", res.Warnings)
	}
}

func TestBrokenLock(t *testing.T) {
	root := tree(t, map[string]string{"composer.lock": "{broken"})
	if res := scanTree(t, root, Options{}); len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "composer.lock") {
		t.Errorf("warnings %v", res.Warnings)
	}
}

func TestParseEnv(t *testing.T) {
	env, lines := parseEnv([]byte("# c\nexport APP_DEBUG=true # on\nAPP_NAME=\"My App\"\nEMPTY=\nBAD LINE\n"))
	if env["APP_DEBUG"] != "true" || env["APP_NAME"] != "My App" || env["EMPTY"] != "" || len(env) != 3 {
		t.Errorf("%q", env)
	}
	if lines["APP_DEBUG"] != 2 || lines["EMPTY"] != 4 {
		t.Errorf("lines %v", lines)
	}
}

func TestComposerStatus(t *testing.T) {
	api := osvtest.NewServer(t)
	ctx := context.Background()
	o := func() *OSV { return &OSV{HTTP: api.Client(), Base: api.URL, CacheDir: t.TempDir()} }
	// composerStatus gives the OSV status for engine.Result.VulnData.
	root := tree(t, map[string]string{"composer.lock": lockFile})
	s := &scan{opts: Options{OSV: o()}, root: root, base: &url.URL{Scheme: "file"}}
	s.loadLock()
	if _, status := s.composerStatus(ctx); status != vulns.StatusOK {
		t.Errorf("composerStatus = %q", status)
	}
	if _, status := (&scan{root: root}).composerStatus(ctx); status != vulns.StatusOff {
		t.Errorf("no OSV client: %q", status)
	}
	if _, status := (&scan{opts: Options{OSV: o()}, root: t.TempDir()}).composerStatus(ctx); status != "" {
		t.Errorf("no composer.lock: %q", status)
	}
}

func TestOSVUnreachable(t *testing.T) {
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

	root := tree(t, map[string]string{"composer.lock": lockFile})
	start := time.Now()
	res := scanTree(t, root, Options{OSV: &OSV{Base: srv.URL, CacheDir: t.TempDir(), Timeout: time.Second}})
	if d := time.Since(start); d > 4*time.Second {
		t.Errorf("took %s", d)
	}
	want := "Composer vulnerability data unreachable, no cached data; known vulnerabilities not checked"
	if hits.Load() != 1 || len(res.Warnings) != 1 || res.Warnings[0] != want {
		t.Errorf("%d requests, warnings %q", hits.Load(), res.Warnings)
	}
}
