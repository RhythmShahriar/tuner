// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// A developer's own key must never send tests to the real feed.
func init() {
	_ = os.Unsetenv("TUNER_WORDFENCE_KEY")
	_ = os.Unsetenv("TUNER_WORDFENCE_API")
}

func TestUpdateWordfence(t *testing.T) {
	feed, err := os.ReadFile("../../vulns/testdata/wordfence/production.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	const key = "wf-cli-key-77aa"
	var hits atomic.Int32
	var auth atomic.Value
	wf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		auth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(feed)
	}))
	defer wf.Close()
	packRelease(t, packCheck, "0.2.0")
	t.Setenv("TUNER_WORDFENCE_API", wf.URL)

	// No key: the feed is never asked for.
	t.Setenv("TUNER_WORDFENCE_KEY", "")
	if code, out, _ := tuner(t, "update"); code != exitOK || hits.Load() != 0 || strings.Contains(out, "Wordfence") {
		t.Errorf("no key: exit %d, %d requests\n%s", code, hits.Load(), out)
	}

	t.Setenv("TUNER_WORDFENCE_KEY", key)
	code, out, errs := tuner(t, "update")
	if code != exitOK || hits.Load() != 1 || auth.Load() != "Bearer "+key ||
		!strings.Contains(out, "Refreshed 1 vulnerability records") ||
		!strings.Contains(out, "Data: WPVulnerability (wpvulnerability.com, CC0); Wordfence Intelligence (Copyright Defiant Inc.; license https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/)") {
		t.Errorf("with key: exit %d, %d requests, auth %v\n%s%s", code, hits.Load(), auth.Load(), out, errs)
	}
	if strings.Contains(out+errs, key) {
		t.Error("the key was printed")
	}
	if code, out, _ := tuner(t, "update", "--help"); code != exitOK || !strings.Contains(out, "TUNER_WORDFENCE_KEY") {
		t.Errorf("help:\n%s", out)
	}
}
