// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/fingerprint"
)

func TestDataStatus(t *testing.T) {
	for _, c := range []struct {
		total, failed, stale int
		want                 string
	}{
		{0, 0, 0, StatusOK},
		{3, 0, 0, StatusOK},
		{3, 1, 0, StatusPartial},
		{3, 0, 1, StatusPartial},
		{3, 3, 0, StatusMissing},
	} {
		if got := DataStatus(c.total, c.failed, c.stale); got != c.want {
			t.Errorf("DataStatus(%d, %d, %d) = %q, want %q", c.total, c.failed, c.stale, got, c.want)
		}
	}
}

func TestAdviseStatus(t *testing.T) {
	fp := fingerprint.Result{Tech: []string{"wordpress"}, Components: []fingerprint.Component{
		{Type: "plugin", Slug: "contact-form-7", Version: "5.3.1"},
		{Type: "plugin", Slug: "akismet", Version: "5.0"},
	}}
	ctx := context.Background()

	f := newFakeAPI(t)
	if _, _, status := newAdvisor(f, t.TempDir()).AdviseStatus(ctx, base, fp); status != StatusOK {
		t.Errorf("all ok: status %q", status)
	}

	// One lookup answers 500: partial.
	f = newFakeAPI(t, map[string]string{"/plugin/akismet/": "!500"})
	_, warnings, status := newAdvisor(f, t.TempDir()).AdviseStatus(ctx, base, fp)
	if status != StatusPartial || len(warnings) != 1 {
		t.Errorf("one 500: status %q, warnings %v", status, warnings)
	}

	// The API hangs: nothing checked.
	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(hang.Close)
	t.Cleanup(func() { close(release) })
	c := &Client{HTTP: &http.Client{Timeout: 200 * time.Millisecond}, CacheDir: t.TempDir(), Pace: -1,
		VulnBase: hang.URL, WPOrgBase: hang.URL, PHPNetBase: hang.URL}
	if _, _, status := (&Advisor{Client: c}).AdviseStatus(ctx, base, fp); status != StatusMissing {
		t.Errorf("hanging API: status %q", status)
	}

	// Nothing to look up is not missing data.
	if _, _, status := newAdvisor(newFakeAPI(t), t.TempDir()).AdviseStatus(ctx, base, fingerprint.Result{}); status != StatusOK {
		t.Errorf("nothing to look up: status %q", status)
	}
}
