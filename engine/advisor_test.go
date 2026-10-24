// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const composerLock = `{"packages": [{"name": "guzzlehttp/guzzle", "version": "7.4.0"}]}`

// composerAdvisor stands in for OSV matching on an exposed composer.lock.
type composerAdvisor struct {
	mu     sync.Mutex
	calls  int
	bodies []string
}

func (a *composerAdvisor) AdviseResponse(_ context.Context, f Finding, body []byte) ([]Finding, []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	a.bodies = append(a.bodies, string(body))
	if f.ID != "leak-composer" || !strings.Contains(string(body), "guzzlehttp/guzzle") {
		return nil, nil
	}
	return []Finding{{
		ID: "vuln-composer-guzzlehttp-guzzle", Title: "guzzlehttp/guzzle 7.4.0 has known vulnerabilities",
		Severity: Critical, URL: f.URL, Path: f.Path,
		Evidence: Evidence{Request: f.Evidence.Request, Status: f.Evidence.Status,
			Matched: []string{"auth token ghp_" + strings.Repeat("a", 36)}},
	}}, []string{"osv: 1 package checked"}
}

func TestResponseAdvisor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/composer.lock" {
			_, _ = w.Write([]byte(composerLock))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	checks := []*Check{
		mustParse(t, `
id: leak-composer
name: composer.lock
severity: low
request: {path: ["/composer.lock"]}
match: {all: [{status: 200}, {words: ['"packages"']}]}
`),
		mustParse(t, envCheck), // does not fire, so the advisor never sees it
	}
	adv := &composerAdvisor{}
	var streamed []string
	res, err := New(checks, Options{HTTPClient: srv.Client(), ResponseAdvisors: []ResponseAdvisor{adv}}).
		Scan(context.Background(), srv.URL, Hooks{Finding: func(f Finding) { streamed = append(streamed, f.ID) }})
	if err != nil {
		t.Fatal(err)
	}
	if adv.calls != 1 || adv.bodies[0] != composerLock {
		t.Fatalf("advisor called %d times with %q", adv.calls, adv.bodies)
	}
	if len(res.Findings) != 2 || res.Findings[0].ID != "vuln-composer-guzzlehttp-guzzle" || res.Findings[1].ID != "leak-composer" {
		t.Fatalf("findings not sorted by severity: %+v", res.Findings)
	}
	f := res.Findings[0]
	if f.Target != res.Target {
		t.Errorf("target %q, want %q", f.Target, res.Target)
	}
	if strings.Contains(strings.Join(f.Evidence.Matched, " "), strings.Repeat("a", 36)) {
		t.Errorf("advisor evidence not redacted: %q", f.Evidence.Matched)
	}
	if len(streamed) != 2 {
		t.Errorf("hook saw %v", streamed)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "osv: 1 package checked") {
		t.Errorf("warnings %q", res.Warnings)
	}
}
