// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/update"

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
		if c := checkForUpdate(context.Background(), "ua", false); c != nil {
			t.Errorf("RHYTHM_OFFLINE=%s: check started", v)
		}
	}
	t.Setenv("RHYTHM_OFFLINE", "")
	if c := checkForUpdate(context.Background(), "ua", true); c != nil {
		t.Errorf("--offline: check started")
	}
	if hits.Load() != 0 {
		t.Errorf("offline checks asked GitHub %d times", hits.Load())
	}
	var out bytes.Buffer
	opts := updatePrompt(checkForUpdate(context.Background(), "ua", false), "", false, &out, &out)
	opts.Wait = 5 * time.Second
	update.PromptAtExit(context.Background(), opts)
	if !strings.Contains(out.String(), "rhythm-tuner is available: 0.1.0 → 9.0.0") {
		t.Errorf("notice %q", out.String())
	}
}

// A machine format or -q never asks "Update now?": a script reading the
// report must not wait on an answer. The terminal view may ask.
func TestUpdatePromptQuietForMachineOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, tc := range []struct {
		format string
		quiet  bool
		want   bool
	}{
		{"json", false, true},
		{"jsonl", false, true},
		{"sarif", false, true},
		{"md", false, true},
		{"", true, true},
		{"", false, false},
	} {
		opts := updatePrompt(nil, tc.format, tc.quiet, &stdout, &stderr)
		if opts.Quiet != tc.want {
			t.Errorf("format %q quiet %v: Quiet %v, want %v", tc.format, tc.quiet, opts.Quiet, tc.want)
		}
		if opts.Stdout != &stdout || opts.Out != &stderr {
			t.Errorf("format %q: writers not passed through", tc.format)
		}
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
