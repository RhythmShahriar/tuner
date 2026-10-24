// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/RhythmShahriar/tuner/internal/release"
)

func TestReleaseUpdaterIdentity(t *testing.T) {
	t.Setenv("RHYTHM_GITHUB_API", "https://ghe.example/api/v3")
	u := releaseUpdater("rhythm-tuner/test", true)
	if u.Repo != release.Repo || u.Binary != release.Binary || u.Current != version {
		t.Errorf("updater for %s/%s at %s", u.Repo, u.Binary, u.Current)
	}
	if u.API != "https://ghe.example/api/v3" || u.UserAgent != "rhythm-tuner/test" || !u.Offline {
		t.Errorf("API %q, UA %q, offline %v", u.API, u.UserAgent, u.Offline)
	}
}

// RHYTHM_OFFLINE goes through the kit now: any value but "" and "0"
// turns the check off ("false" included) and no request is sent.
func TestUpdateCheckHonoursKitOffline(t *testing.T) {
	var hits atomic.Int32
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"tag_name":"v9.0.0","assets":[]}`))
	}))
	defer gh.Close()
	t.Setenv("RHYTHM_GITHUB_API", gh.URL)
	t.Setenv("CI", "")
	t.Setenv("RHYTHM_NO_UPDATE_CHECK", "")
	t.Setenv("RHYTHM_CONFIG_DIR", t.TempDir())
	old := version
	version = "0.1.0"
	defer func() { version = old }()

	for _, v := range []string{"1", "true", "false", "yes"} {
		t.Setenv("RHYTHM_OFFLINE", v)
		if msg, ok := <-checkForUpdate(context.Background(), "ua", false); ok {
			t.Errorf("RHYTHM_OFFLINE=%s: notice %q", v, msg)
		}
	}
	t.Setenv("RHYTHM_OFFLINE", "")
	if msg, ok := <-checkForUpdate(context.Background(), "ua", true); ok {
		t.Errorf("--offline: notice %q", msg)
	}
	if hits.Load() != 0 {
		t.Errorf("offline checks asked GitHub %d times", hits.Load())
	}
	msg := <-checkForUpdate(context.Background(), "ua", false)
	if !strings.Contains(msg, "rhythm-tuner is available: 0.1.0 → 9.0.0") {
		t.Errorf("notice %q", msg)
	}
}

// The binary only names its releases; the Sigstore check stays in
// internal/release/signature so it is not linked into rhythm-tuner.
func TestBinaryDoesNotLinkSigstore(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go list")
	}
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH")
	}
	out, err := exec.Command(gobin, "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.Contains(dep, "sigstore") || strings.HasSuffix(dep, "/kit/sigverify") {
			t.Fatalf("rhythm-tuner imports %s", dep)
		}
	}
}
