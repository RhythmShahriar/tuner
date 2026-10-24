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
	"time"

	"github.com/RhythmShahriar/tuner/vulns/osv/osvtest"
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

// A remote scan matches the packages of an exposed composer.lock against
// OSV.dev. The data clients get the scan's --timeout, plus the Wordfence
// feed when TUNER_WORDFENCE_KEY is set.
func TestScanVulnDataWiring(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	osvAPI := osvtest.NewServer(t)
	t.Setenv("TUNER_OSV_API", osvAPI.URL)
	fakeVulnAPI(t)
	lock := `{"packages": [{"name": "guzzlehttp/guzzle", "version": "7.4.1"}, {"name": "acme/clean", "version": "1.0.0"}]}`
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte("<html>home</html>"))
		case "/composer.lock":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(lock))
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	code, out, errs := tuner(t, "scan", site.URL, "--json", "--no-check-updates")
	if code != exitOK || !strings.Contains(out, `"id": "vuln-composer-guzzlehttp-guzzle"`) || osvAPI.Hits.Load() == 0 {
		t.Errorf("exit %d, %d OSV requests, stderr %s\n%.3000s", code, osvAPI.Hits.Load(), errs, out)
	}
	// --id narrows these findings too.
	if _, out, _ := tuner(t, "scan", site.URL, "--json", "--no-check-updates", "--id", "leak-*"); strings.Contains(out, "vuln-composer-") {
		t.Errorf("--id leak-* kept a Composer finding:\n%.2000s", out)
	}

	t.Setenv("TUNER_WORDFENCE_KEY", "wf-test-key")
	t.Setenv("TUNER_WORDFENCE_API", "http://127.0.0.1:1")
	p, err := planScan([]string{site.URL, "--timeout", "3s", "--no-config", "--no-check-updates"}, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if p.vulns == nil || p.vulns.Timeout != 3*time.Second || p.vulns.Wordfence == nil || p.vulns.Wordfence.Key != "wf-test-key" {
		t.Errorf("vulns client: %+v", p.vulns)
	}
	if p.osv == nil || p.osv.Timeout != 3*time.Second || len(p.engine.ResponseAdvisors) != 1 {
		t.Errorf("osv client %+v, %d response advisors", p.osv, len(p.engine.ResponseAdvisors))
	}
	p, err = planScan([]string{site.URL, "--no-vulns", "--no-config", "--no-check-updates"}, strings.NewReader(""))
	if err != nil || p.vulns != nil || len(p.engine.ResponseAdvisors) != 0 {
		t.Errorf("--no-vulns: %v, %+v, %d response advisors", err, p.vulns, len(p.engine.ResponseAdvisors))
	}
}
