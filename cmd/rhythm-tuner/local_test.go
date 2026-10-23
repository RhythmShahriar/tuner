package main

import (
	"encoding/json"
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

	// Only local findings, and a baseline hides them all.
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
