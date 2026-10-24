// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/RhythmShahriar/tuner/fingerprint"
)

// A plugin slug that is a Windows device name still gets a cache file
// that update refreshes under its real slug.
func TestWindowsReservedSlug(t *testing.T) {
	f := newFakeAPI(t, map[string]string{"/plugin/con/": `{"error":0,"data":{"name":"Con","vulnerability":[]}}`})
	dir := t.TempDir()
	a := newAdvisor(f, dir)
	a.Advise(context.Background(), base, fingerprint.Result{Components: []fingerprint.Component{{Type: "plugin", Slug: "con", Version: "1.0"}}})
	if _, err := os.Stat(filepath.Join(dir, "wpvulnerability", "plugin", "con_.json")); err != nil {
		t.Fatalf("cache file: %v", err)
	}
	f.mu.Lock()
	f.paths = nil
	f.mu.Unlock()
	if ok, failed, err := newAdvisor(f, dir).Client.Refresh(context.Background()); ok == 0 || failed != 0 || err != nil {
		t.Errorf("Refresh: %d ok, %d failed, %v", ok, failed, err)
	}
	if !f.requested("/plugin/con/") || f.requested("/plugin/con_/") {
		t.Errorf("Refresh asked for the wrong slug: %v", f.paths)
	}
}
