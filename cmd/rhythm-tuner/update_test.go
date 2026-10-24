// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
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
	entry := filepath.Join(cacheHome, "rhythm", "tuner", "vulns", "osv", "packagist", "laravel_framework@8.0.0.json")
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
