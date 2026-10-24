// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A file name in the site tree reaches the prefetch warnings, so it must
// not carry a terminal escape through.
func TestUpdatePrefetchCleansWarnings(t *testing.T) {
	packRelease(t, packCheck, "0.2.0") // sets XDG_CACHE_HOME
	fakeVulnAPI(t)
	root, php := localSite(t)
	dir := filepath.Join(root, "wp-content")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "x\x1b[31mRED.php"), 0o600); err != nil {
		t.Skipf("no named pipes here: %v", err)
	}
	_, out, errs := tuner(t, "update", "--prefetch", root, "--php", php)
	if strings.ContainsRune(out+errs, '\x1b') {
		t.Errorf("raw escape in the output:\n%q\n%q", out, errs)
	}
	if !strings.Contains(errs, "named pipe") || !strings.Contains(errs, "RED.php") {
		t.Errorf("the skipped pipe isn't reported: %q", errs)
	}
}
