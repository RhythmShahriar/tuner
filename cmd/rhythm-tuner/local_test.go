// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// localSite writes a small WordPress root with a stray .env and a php
// stand-in that reports 8.3.6.
func localSite(t *testing.T) (root, php string) {
	t.Helper()
	root = t.TempDir()
	for p, body := range map[string]string{
		"wp-includes/version.php": "<?php $wp_version = '6.4.1';",
		"wp-config.php":           "<?php define('DISALLOW_FILE_EDIT', true); define('FORCE_SSL_ADMIN', true); $table_prefix = 'x_';",
		".env":                    "DB_PASSWORD=" + rawSecret + "\n",
	} {
		full := filepath.Join(root, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(body), 0o600)
	}
	php = filepath.Join(t.TempDir(), "php")
	os.WriteFile(php, []byte("#!/bin/sh\necho 8.3.6\n"), 0o700) //nolint:gosec // test executable
	return root, php
}

func TestLocalScan(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as php")
	}
	t.Setenv("TUNER_OSV_API", "http://127.0.0.1:1")
	root, php := localSite(t)

	code, out, errs := tuner(t, "scan", root, "--json", "--php", php, "--fail-on", "high")
	if code != exitFindings {
		t.Fatalf("exit %d, stderr %s\n%s", code, errs, out)
	}
	var r struct {
		Target      string
		Fingerprint struct {
			Tech      []string
			WordPress string `json:"wordpress_version"`
			PHP       string `json:"php_version"`
		}
		Findings []struct{ ID, URL string }
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if r.Target != root || r.Fingerprint.WordPress != "6.4.1" || r.Fingerprint.PHP != "8.3.6" {
		t.Errorf("report: %+v", r)
	}
	var found []string
	for _, f := range r.Findings {
		found = append(found, f.ID)
		if !strings.HasPrefix(f.URL, "file://") {
			t.Errorf("%s url %s", f.ID, f.URL)
		}
	}
	if !strings.Contains(strings.Join(found, " "), "local-dotenv") || !strings.Contains(strings.Join(found, " "), "local-wp-salts") {
		t.Errorf("findings %v", found)
	}
	if strings.Contains(out, rawSecret) {
		t.Error("report leaks the secret")
	}

	// Only local findings; a baseline hides them all.
	base := filepath.Join(t.TempDir(), "base.json")
	os.WriteFile(base, []byte(out), 0o600)
	code, out, errs = tuner(t, "scan", root, "--json", "--php", php, "--no-vulns", "--id", "local-*", "--baseline", base, "--fail-on", "info")
	if code != exitOK || !strings.Contains(out, `"findings": []`) && !strings.Contains(out, `"findings": null`) {
		t.Errorf("baselined: exit %d, stderr %s\n%s", code, errs, out)
	}

	// Terminal view.
	code, out, _ = tuner(t, "scan", root, "--plain", "--php", php, "--offline")
	if code != exitOK || !strings.Contains(out, "WordPress 6.4.1 · PHP 8.3.6") || !strings.Contains(out, ".env file in the web root") {
		t.Errorf("plain: exit %d\n%s", code, out)
	}
}

func TestLocalScanErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	os.WriteFile(file, nil, 0o600)
	for _, target := range []string{filepath.Join(dir, "missing"), "./no-such-dir", file} {
		if code, _, errs := tuner(t, "scan", target); code != exitUsage || !strings.Contains(errs, "directory") {
			t.Errorf("%s: exit %d, %s", target, code, errs)
		}
	}
}

// distroPHPAPI fakes WPVulnerability and php.net with one critical PHP 8.1
// flaw fixed in 8.1.22, so an Ubuntu 8.1.2 build gets a likely finding.
func distroPHPAPI(t *testing.T) {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/php/8.1.2/":
			w.Write([]byte(`{"error":0,"data":{"name":"PHP 8.1","vulnerability":[{"uuid":"p1","name":"PHP 8.1 < 8.1.22",
				"operator":{"max_version":"8.1.22","max_operator":"lt","unfixed":0},
				"source":[{"id":"CVE-2023-3824","name":"CVE-2023-3824","link":"https://www.cve.org/x"}],
				"impact":{"cvss3":{"score":"9.4","severity":"critical"},"kev":false}}]}}`))
		case "/releases/states.php":
			w.Write([]byte(`{"8":{"8.4":{"state":"stable","security_support_end":"2028-12-31T00:00:00+00:00"},
				"8.1":{"state":"security","security_support_end":"2029-12-31T00:00:00+00:00"}}}`))
		default:
			w.Write([]byte(`{"error":0,"data":{"vulnerability":[]}}`))
		}
	}))
	t.Cleanup(api.Close)
	for _, env := range []string{"TUNER_VULN_API", "TUNER_WPORG_API", "TUNER_PHPNET_API", "TUNER_OSV_API"} {
		t.Setenv(env, api.URL)
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
}

// A likely finding fails --fail-on by default; --min-confidence confirmed
// lets the gate pass and still reports it.
func TestMinConfidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as php")
	}
	distroPHPAPI(t)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "wp-includes"), 0o755)
	os.WriteFile(filepath.Join(root, "wp-includes", "version.php"), []byte("<?php $wp_version = '6.4.1';"), 0o600)
	php := filepath.Join(t.TempDir(), "php")
	os.WriteFile(php, []byte("#!/bin/sh\necho 8.1.2-1ubuntu2.23\n"), 0o700) //nolint:gosec // test executable

	args := []string{"scan", root, "--php", php, "--plain", "--id", "vuln-*", "--fail-on", "high"}
	code, out, errs := tuner(t, args...)
	if code != exitFindings || !strings.Contains(out, "likely") || !strings.Contains(out, "CVE-2023-3824") {
		t.Fatalf("default: exit %d, stderr %s\n%s", code, errs, out)
	}
	code, out, errs = tuner(t, append(args, "--min-confidence", "confirmed")...)
	if code != exitOK || !strings.Contains(out, "CVE-2023-3824") {
		t.Errorf("confirmed: exit %d, stderr %s\n%s", code, errs, out)
	}
	if code, _, _ := tuner(t, append(args, "--min-confidence", "likely")...); code != exitFindings {
		t.Errorf("likely: exit %d", code)
	}
	if code, _, errs := tuner(t, append(args, "--min-confidence", "sure")...); code != exitUsage || !strings.Contains(errs, "want confirmed or likely") {
		t.Errorf("bad value: exit %d, %s", code, errs)
	}
}

// --fail-on-new follows --min-confidence like --fail-on: a new likely
// finding fails it by default, not with confirmed.
func TestMinConfidenceFailOnNew(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as php")
	}
	needScanFlags(t, "since", "fail-on-new")
	distroPHPAPI(t)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "wp-includes"), 0o755)
	os.WriteFile(filepath.Join(root, "wp-includes", "version.php"), []byte("<?php $wp_version = '6.4.1';"), 0o600)
	php := filepath.Join(t.TempDir(), "php")
	os.WriteFile(php, []byte("#!/bin/sh\necho 8.1.2-1ubuntu2.23\n"), 0o700) //nolint:gosec // test executable
	before := filepath.Join(t.TempDir(), "before.json")
	if code, _, errs := tuner(t, "scan", root, "--php", php, "--id", "local-dotenv", "-o", before, "-q"); code != exitOK {
		t.Fatalf("before: exit %d: %s", code, errs)
	}

	args := []string{"scan", root, "--php", php, "--plain", "--id", "vuln-*", "--since", before, "--fail-on-new", "high"}
	if code, out, errs := tuner(t, args...); code != exitFindings {
		t.Errorf("default: exit %d, stderr %s\n%s", code, errs, out)
	}
	if code, out, errs := tuner(t, append(args, "--min-confidence", "confirmed")...); code != exitOK || !strings.Contains(errs, "new") {
		t.Errorf("confirmed: exit %d, stderr %s\n%s", code, errs, out)
	}
}
