// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package osv

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/vulns"
	"github.com/RhythmShahriar/tuner/vulns/cache"
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

func TestParseLock(t *testing.T) {
	pkgs, err := ParseLock([]byte(lockFile))
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{{"laravel/framework", "8.0.0"}, {"monolog/monolog", "2.9.1"}, {"acme/abandoned", "1.0.0"}, {"phpunit/phpunit", "9.6.0"}}
	if !slices.Equal(pkgs, want) {
		t.Errorf("got %v", pkgs)
	}
	for _, bad := range []string{"not json", "{broken", `{"packages": "x"}`} {
		if _, err := ParseLock([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	// vendor/composer/installed.json: Composer 2 wraps the list, Composer 1 doesn't.
	for _, installed := range []string{
		`{"packages":[{"name":"GuzzleHttp/Guzzle","version":"7.4.1"}],"dev":true}`,
		` [{"name":"guzzlehttp/guzzle","version":"v7.4.1"}]`,
	} {
		if pkgs, err := ParseLock([]byte(installed)); err != nil || !slices.Equal(pkgs, []Package{{"guzzlehttp/guzzle", "7.4.1"}}) {
			t.Errorf("%s: %v %v", installed, pkgs, err)
		}
	}
	if pkgs, err := ParseLock([]byte(`{}`)); err != nil || len(pkgs) != 0 {
		t.Errorf("empty lock: %v %v", pkgs, err)
	}
}

func TestOSVCorruptCache(t *testing.T) {
	api := osvtest.NewServer(t)
	cacheDir := t.TempDir()
	pkgs := []Package{{"laravel/framework", "8.0.0"}, {"acme/abandoned", "1.0.0"}, {"monolog/monolog", "2.9.1"}}
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(cacheDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("packagist/laravel~framework@8.0.0.json", `null`)
	write("packagist/acme~abandoned@1.0.0.json", `{"fetched":"2026-10-22T00:00:00Z","data":["GHSA-cccc"]}`) // format 0
	write("packagist/monolog~monolog@2.9.1.json", `{}`)
	write("vulns/GHSA-aaaa.json", `{"format":1,"fetched":"2026-10-22T00:00:00Z","data":null}`)
	write("vulns/GHSA-bbbb.json", `["not","an","entry"]`)

	// Offline: every bad entry is missing; nothing crashes.
	o := &Client{CacheDir: cacheDir, Offline: true}
	found, failed, _ := o.Query(context.Background(), pkgs)
	if len(found) != 0 || failed != 3 {
		t.Errorf("offline: found %v, %d failed", found, failed)
	}

	// Online: fetched again, then served from the rewritten cache.
	o = &Client{HTTP: api.Client(), Base: api.URL, CacheDir: cacheDir}
	found, failed, err := o.Query(context.Background(), pkgs)
	if failed != 0 || err != nil || len(found[pkgs[0]]) != 2 || len(found[pkgs[1]]) != 1 {
		t.Fatalf("online: found %v, %d failed, %v", found, failed, err)
	}
	api.Down.Store(true)
	o = &Client{CacheDir: cacheDir, Offline: true}
	if found, failed, _ = o.Query(context.Background(), pkgs); failed != 0 || len(found[pkgs[0]]) != 2 {
		t.Errorf("offline after refetch: found %v, %d failed", found, failed)
	}
}

func TestOSVStatus(t *testing.T) {
	api := osvtest.NewServer(t)
	cacheDir := t.TempDir()
	ctx := context.Background()
	pkgs := []Package{{"laravel/framework", "8.0.0"}, {"monolog/monolog", "2.9.1"}}
	o := func() *Client { return &Client{HTTP: api.Client(), Base: api.URL, CacheDir: cacheDir} }

	if r := o().Check(ctx, pkgs); r.Status() != vulns.StatusOK || r.Total != 2 {
		t.Errorf("all ok: %+v", r)
	}

	// Past the TTL with the API down: stale copies, so partial.
	for _, dir := range []string{"packagist", "vulns"} {
		ents, _ := os.ReadDir(filepath.Join(cacheDir, dir))
		for _, e := range ents {
			p := filepath.Join(cacheDir, dir, e.Name())
			var c cache.Entry[json.RawMessage]
			if err := cache.ReadJSON(p, &c); err != nil {
				t.Fatal(err)
			}
			c.Fetched = c.Fetched.Add(-48 * time.Hour)
			if err := cache.WriteJSON(p, c); err != nil {
				t.Fatal(err)
			}
		}
	}
	api.Down.Store(true)
	if r := o().Check(ctx, pkgs); r.Status() != vulns.StatusPartial || r.Stale != 2 || r.Failed != 0 {
		t.Errorf("stale: %+v", r)
	}

	// Nothing cached and the API down: missing.
	if r := (&Client{HTTP: api.Client(), Base: api.URL, CacheDir: t.TempDir()}).Check(ctx, pkgs); r.Status() != vulns.StatusMissing {
		t.Errorf("down: %+v", r)
	}
}

func TestOSVRefresh(t *testing.T) {
	api := osvtest.NewServer(t)
	cacheDir := t.TempDir()
	ctx := context.Background()
	o := &Client{HTTP: api.Client(), Base: api.URL, CacheDir: cacheDir}
	if ok, failed, err := o.Refresh(ctx); ok+failed != 0 || err != nil {
		t.Errorf("empty cache: %d %d %v", ok, failed, err)
	}

	// An entry from before keys were stored: the file name is enough.
	p := filepath.Join(cacheDir, "packagist", "laravel~framework@8.0.0.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"fetched":"2026-10-23T00:00:00Z","data":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	hits := api.Hits.Load()
	ok, failed, err := o.Refresh(ctx)
	if ok != 3 || failed != 0 || err != nil || api.Hits.Load()-hits != 3 {
		t.Errorf("refresh: ok %d failed %d err %v, %d requests", ok, failed, err, api.Hits.Load()-hits)
	}
	store := &cache.Store{Dir: cacheDir, Format: cacheFormat}
	if e, ok, _ := cache.Read[[]string](store, "packagist", "laravel/framework@8.0.0"); !ok || len(e.Data) != 2 || e.Key != "laravel/framework@8.0.0" {
		t.Errorf("refreshed entry: %+v", e)
	}

	// The API down: failures are counted, the cached copies kept.
	api.Down.Store(true)
	if ok, failed, _ := o.Refresh(ctx); ok != 0 || failed != 3 {
		t.Errorf("down: ok %d failed %d", ok, failed)
	}
	if _, ok, _ := cache.Read[[]string](store, "packagist", "laravel/framework@8.0.0"); !ok {
		t.Error("down: cached copy lost")
	}
	if _, _, err := (&Client{CacheDir: cacheDir, Offline: true}).Refresh(ctx); err == nil {
		t.Error("offline refresh should fail")
	}
}

func TestParsePackageKey(t *testing.T) {
	for key, want := range map[string]Package{
		"foo_bar/baz@1.0":         {"foo_bar/baz", "1.0"},
		"foo~bar_baz@1.0":         {"foo/bar_baz", "1.0"}, // file name, "/" escaped
		"laravel_framework@8.0.0": {"laravel/framework", "8.0.0"},
	} {
		if got, ok := parsePackageKey(key); !ok || got != want {
			t.Errorf("parsePackageKey(%q) = %v %v, want %v", key, got, ok, want)
		}
	}
	for _, key := range []string{"", "@1.0", "foo/bar@", "foo"} {
		if _, ok := parsePackageKey(key); ok {
			t.Errorf("parsePackageKey(%q) accepted", key)
		}
	}
}
