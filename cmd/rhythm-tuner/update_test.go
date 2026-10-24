// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/RhythmShahriar/tuner/vulns/osv/osvtest"
)

func TestUpdateRefreshesOSV(t *testing.T) {
	var batches, details atomic.Int32
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			batches.Add(1)
			w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-aaaa"}]}]}`))
		case r.URL.Path == "/v1/vulns/GHSA-aaaa":
			details.Add(1)
			w.Write([]byte(`{"id":"GHSA-aaaa","summary":"Query binding exploitation"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer osv.Close()
	packRelease(t, packCheck, "0.2.0") // sets XDG_CACHE_HOME
	cacheHome := os.Getenv("XDG_CACHE_HOME")
	t.Setenv("TUNER_OSV_API", osv.URL)

	if code, out, _ := tuner(t, "update"); code != exitOK || !strings.Contains(out, "Nothing cached yet") || batches.Load() != 0 {
		t.Errorf("empty cache: exit %d, %d queries\n%s", code, batches.Load(), out)
	}

	// A package a scan cached earlier is asked about again.
	entry := filepath.Join(cacheHome, "rhythm", "tuner", "vulns", "osv", "packagist", "laravel~framework@8.0.0.json")
	if err := os.MkdirAll(filepath.Dir(entry), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry, []byte(`{"format":1,"key":"laravel/framework@8.0.0","fetched":"2026-10-23T00:00:00Z","data":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := tuner(t, "update")
	if code != exitOK || batches.Load() != 1 || details.Load() != 1 {
		t.Fatalf("exit %d, %d queries, %d details\n%s%s", code, batches.Load(), details.Load(), out, errs)
	}
	if !strings.Contains(out, "Refreshed 2 Composer advisory records") || !strings.Contains(out, "OSV.dev") ||
		strings.Contains(out, "vulnerability records") {
		t.Errorf("output:\n%s", out)
	}
	b, _ := os.ReadFile(entry)
	if !strings.Contains(string(b), "GHSA-aaaa") {
		t.Errorf("entry not rewritten: %s", b)
	}
}

// fakeVulnAPI serves WPVulnerability, wordpress.org and php.net answers:
// contact-form-7 below 5.3.2 is vulnerable, everything else is clean. It
// counts the requests it gets and fails them all while down is set.
func fakeVulnAPI(t *testing.T) (hits *atomic.Int32, down *atomic.Bool) {
	t.Helper()
	hits, down = &atomic.Int32{}, &atomic.Bool{}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if down.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		switch r.URL.Path {
		case "/plugin/contact-form-7/":
			w.Write([]byte(`{"error":0,"data":{"name":"Contact Form 7","closed":0,"vulnerability":[{"uuid":"u1",
				"operator":{"max_version":"5.3.2","max_operator":"lt","unfixed":"0"},
				"source":[{"id":"CVE-2020-35489","name":"CVE-2020-35489","link":"https://www.cve.org/x"}],
				"impact":{"cvss3":{"score":"10.0","severity":"critical"},"kev":false}}]}}`))
		case "/plugins/info/1.2/":
			w.Write([]byte(`{"version":"6.2.3","last_updated":"2026-10-21 8:43am GMT"}`))
		case "/releases/states.php":
			w.Write([]byte(`{"8":{"8.3":{"state":"security","security_support_end":"2027-12-31T00:00:00+00:00"},
				"8.4":{"state":"stable","security_support_end":"2028-12-31T00:00:00+00:00"}}}`))
		case "/core/version-check/1.7/":
			w.Write([]byte(`{"offers":[{"current":"6.4.1"}]}`))
		default:
			w.Write([]byte(`{"error":0,"data":{"vulnerability":[]}}`))
		}
	}))
	t.Cleanup(api.Close)
	t.Setenv("TUNER_VULN_API", api.URL)
	t.Setenv("TUNER_WPORG_API", api.URL)
	t.Setenv("TUNER_PHPNET_API", api.URL)
	return hits, down
}

func TestUpdatePrefetchLocal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as php")
	}
	packRelease(t, packCheck, "0.2.0") // sets XDG_CACHE_HOME
	hits, down := fakeVulnAPI(t)
	osvAPI := osvtest.NewServer(t)
	t.Setenv("TUNER_OSV_API", osvAPI.URL)
	root, php := localSite(t)
	os.WriteFile(filepath.Join(root, "composer.lock"), []byte(`{"packages":[{"name":"guzzlehttp/guzzle","version":"7.4.1"},{"name":"monolog/monolog","version":"2.9.1"}]}`), 0o600)
	plugin := filepath.Join(root, "wp-content", "plugins", "contact-form-7", "wp-contact-form-7.php")
	os.MkdirAll(filepath.Dir(plugin), 0o755)
	os.WriteFile(plugin, []byte("<?php\n/*\nPlugin Name: Contact Form 7\nVersion: 5.3.1\n*/"), 0o600)

	// Cold cache: an offline scan has nothing to match against.
	if _, out, errs := tuner(t, "scan", root, "--json", "--offline", "--php", php); !strings.Contains(errs+out, "not cached") {
		t.Fatalf("cold offline scan: %s%s", errs, out)
	}

	code, out, errs := tuner(t, "update", "--prefetch", root, "--php", php)
	if code != exitOK || !strings.Contains(out, "Prefetched "+root+": WordPress 6.4.1, 1 plugin, PHP 8.3.6, 2 Composer packages") ||
		!strings.Contains(out, "Data: WPVulnerability (wpvulnerability.com, CC0); OSV.dev") || strings.Contains(out, "Nothing cached") {
		t.Fatalf("prefetch: exit %d, stderr %s\n%s", code, errs, out)
	}
	if hits.Load() == 0 {
		t.Fatal("prefetch made no requests")
	}

	// Now offline works with the APIs down and makes no requests.
	down.Store(true)
	osvAPI.Down.Store(true)
	n := hits.Load() + osvAPI.Hits.Load()
	code, out, errs = tuner(t, "scan", root, "--json", "--offline", "--php", php, "--id", "vuln-*")
	if code != exitOK || !strings.Contains(out, "vuln-plugin-contact-form-7") || !strings.Contains(out, "vuln-composer-guzzlehttp-guzzle") ||
		strings.Contains(errs+out, "not cached") || hits.Load()+osvAPI.Hits.Load() != n {
		t.Errorf("offline scan after prefetch: exit %d, %d requests, stderr %s\n%s", code, hits.Load()-n, errs, out)
	}

	// A fresh cache isn't fetched again.
	down.Store(false)
	osvAPI.Down.Store(false)
	n = hits.Load() + osvAPI.Hits.Load()
	if code, _, _ := tuner(t, "update", "--prefetch", root, "--php", php); code != exitOK || hits.Load()+osvAPI.Hits.Load() != n {
		t.Errorf("second prefetch: exit %d, %d requests", code, hits.Load()+osvAPI.Hits.Load()-n)
	}

	// OSV.dev down with nothing cached: the prefetch fails and says why.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	osvAPI.Down.Store(true)
	if code, _, errs := tuner(t, "update", "--prefetch", root, "--php", php); code != exitError || !strings.Contains(errs, "2 Composer packages") {
		t.Errorf("prefetch with OSV down: exit %d, stderr %s", code, errs)
	}
}

func TestUpdatePrefetchRemote(t *testing.T) {
	packRelease(t, packCheck, "0.2.0")
	_, down := fakeVulnAPI(t)
	var siteHits atomic.Int32
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siteHits.Add(1)
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<link href="/wp-content/plugins/contact-form-7/s.css?ver=5.3.1">`))
		case "/wp-content/plugins/contact-form-7/readme.txt":
			w.Write([]byte("Stable tag: 5.3.1\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()

	code, out, errs := tuner(t, "update", "--prefetch", site.URL)
	if code != exitOK || !strings.Contains(out, "Prefetched "+site.URL+": 1 plugin") {
		t.Fatalf("prefetch: exit %d, stderr %s\n%s", code, errs, out)
	}
	// No checks ran: a handful of fingerprint requests, not the whole set.
	if n := siteHits.Load(); n > 30 {
		t.Errorf("prefetch sent %d requests to the site", n)
	}
	down.Store(true)
	code, out, errs = tuner(t, "scan", site.URL, "--json", "--offline", "--id", "vuln-*")
	if code != exitOK || !strings.Contains(out, "vuln-plugin-contact-form-7") || strings.Contains(errs+out, "not cached") {
		t.Errorf("offline scan after prefetch: exit %d, stderr %s\n%s", code, errs, out)
	}

	// With the data service down, a cold prefetch fails and says why.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	if code, _, errs := tuner(t, "update", "--prefetch", site.URL); code != exitError || !strings.Contains(errs, "vulnerability data") {
		t.Errorf("prefetch with API down: exit %d, stderr %s", code, errs)
	}
}

func TestUpdateUsage(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"update", "--clean"}, "unknown flag --clean; did you mean --clear?"},
		{[]string{"update", "--pre"}, "unknown flag --pre; did you mean --prefetch?"},
		{[]string{"update", "--offline"}, "unknown flag --offline; update always fetches"},
		{[]string{"update", "--frobnicate"}, "unknown flag --frobnicate\n"},
		{[]string{"update", "--prefetch"}, "--prefetch needs a site or a folder"},
		{[]string{"update", "example.com"}, "update takes no targets; to cache data for example.com, run: rhythm tuner update --prefetch example.com"},
		{[]string{"update", "--prefetch", "./no-such-dir"}, "no such directory"},
		{[]string{"update", "--clear", "--prefetch", "example.com"}, "pick one of --clear and --prefetch"},
	}
	for _, c := range cases {
		code, out, errs := tuner(t, c.args...)
		if code != exitUsage || !strings.Contains(errs, c.want) || out != "" {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want %q", c.args, code, out, errs, c.want)
		}
		if strings.Contains(errs, "flag provided but not defined") || strings.Contains(errs, "Usage of") {
			t.Errorf("%v: raw flag package text: %s", c.args, errs)
		}
	}
	for _, h := range []string{"--help", "-h"} {
		if code, out, _ := tuner(t, "update", h); code != exitOK || !strings.Contains(out, "--prefetch <dir|url>") {
			t.Errorf("update %s: exit %d\n%s", h, code, out)
		}
	}
}

func TestClosestFlag(t *testing.T) {
	known := []string{"clear", "prefetch", "php"}
	for in, want := range map[string]string{"cleer": "clear", "prefech": "prefetch", "ph": "php", "pref": "prefetch", "verbose": "", "": ""} {
		if got := closestFlag(in, known); got != want {
			t.Errorf("closestFlag(%q) = %q, want %q", in, got, want)
		}
	}
}
