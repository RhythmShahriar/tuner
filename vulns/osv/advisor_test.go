// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package osv

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/vulns"
	"github.com/RhythmShahriar/tuner/vulns/osv/osvtest"
)

// exposedLock serves files the way a misconfigured site does and returns
// the leak-composer-manifest finding the engine reports for path, with
// the body it saw.
func exposedLock(t *testing.T, files map[string]string, path string) (engine.Finding, []byte) {
	t.Helper()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(site.Close)
	resp, err := site.Client().Get(site.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return engine.Finding{
		ID: "leak-composer-manifest", Title: "Composer manifest exposed", Severity: engine.Low, Confidence: "high",
		URL: site.URL + path, Path: path, Evidence: engine.Evidence{Request: "GET " + path, Status: resp.StatusCode},
	}, body
}

const guzzleLock = `{"packages":[{"name":"guzzlehttp/guzzle","version":"7.4.1"},{"name":"monolog/monolog","version":"2.9.1"}]}`

func TestComposerAdvisor(t *testing.T) {
	api := osvtest.NewServer(t)
	a := &ComposerAdvisor{Client: &Client{HTTP: api.Client(), Base: api.URL, CacheDir: t.TempDir()}}
	ctx := context.Background()

	leak, body := exposedLock(t, map[string]string{"/composer.lock": guzzleLock}, "/composer.lock")
	findings, warnings := a.AdviseResponse(ctx, leak, body)
	if len(findings) != 1 || len(warnings) != 0 {
		t.Fatalf("findings %+v, warnings %v", findings, warnings)
	}
	f := findings[0]
	if f.ID != "vuln-composer-guzzlehttp-guzzle" || f.Title != "guzzlehttp/guzzle 7.4.1: 3 known vulnerabilities (from exposed composer.lock)" ||
		f.Severity != engine.High || f.Source != Source || f.URL != leak.URL || f.Path != "/composer.lock" || f.Evidence.Status != 200 ||
		len(f.Advisories) != 3 || !slices.Equal(f.Advisories[0].CVEs, []string{"CVE-2022-29248"}) ||
		!strings.Contains(f.Fix, "Update guzzlehttp/guzzle to 7.4.5 or later") ||
		!slices.Contains(f.Evidence.Matched, "version from /composer.lock") {
		t.Errorf("finding: %+v", f)
	}
	if _, ok := vulns.RuleFor(Rules(), f.ID); !ok {
		t.Errorf("%s has no rule", f.ID)
	}

	// Composer 2's installed.json works the same way.
	leak, body = exposedLock(t, map[string]string{"/vendor/composer/installed.json": `{"packages":[{"name":"guzzlehttp/guzzle","version":"v7.4.1"}]}`},
		"/vendor/composer/installed.json")
	if findings, _ := a.AdviseResponse(ctx, leak, body); len(findings) != 1 || !strings.HasSuffix(findings[0].Title, "(from exposed installed.json)") {
		t.Errorf("installed.json: %+v", findings)
	}
}

func TestComposerAdvisorNegative(t *testing.T) {
	api := osvtest.NewServer(t)
	a := &ComposerAdvisor{Client: &Client{HTTP: api.Client(), Base: api.URL, CacheDir: t.TempDir()}}
	ctx := context.Background()

	// No vulnerable packages: nothing to add to the leak finding.
	leak, body := exposedLock(t, map[string]string{"/composer.lock": `{"packages":[{"name":"monolog/monolog","version":"2.9.1"}]}`}, "/composer.lock")
	if findings, warnings := a.AdviseResponse(ctx, leak, body); len(findings) != 0 || len(warnings) != 0 {
		t.Errorf("clean lock: %+v %v", findings, warnings)
	}

	// A malformed (or truncated) lock is a warning, never a crash or a finding.
	leak, body = exposedLock(t, map[string]string{"/composer.lock": `{"packages":[{"name":"guzzlehttp/guzzle","vers`}, "/composer.lock")
	findings, warnings := a.AdviseResponse(ctx, leak, body)
	if len(findings) != 0 || len(warnings) != 1 || !strings.HasPrefix(warnings[0], "couldn't read the exposed /composer.lock") {
		t.Errorf("malformed lock: %+v %v", findings, warnings)
	}

	// Other findings, and composer.json (constraints, not versions), are ignored without a request.
	hits := api.Hits.Load()
	leak, body = exposedLock(t, map[string]string{"/composer.json": `{"require":{"guzzlehttp/guzzle":"^7.0"}}`}, "/composer.json")
	if findings, warnings := a.AdviseResponse(ctx, leak, body); len(findings) != 0 || len(warnings) != 0 {
		t.Errorf("composer.json: %+v %v", findings, warnings)
	}
	other := engine.Finding{ID: "leak-dotenv", Path: "/composer.lock"}
	if findings, _ := a.AdviseResponse(ctx, other, []byte(guzzleLock)); len(findings) != 0 {
		t.Errorf("leak-dotenv: %+v", findings)
	}
	if api.Hits.Load() != hits {
		t.Error("ignored findings made requests")
	}

	// OSV.dev down and nothing cached: the leak still stands, with a warning.
	api.Down.Store(true)
	leak, body = exposedLock(t, map[string]string{"/composer.lock": guzzleLock}, "/composer.lock")
	a = &ComposerAdvisor{Client: &Client{HTTP: api.Client(), Base: api.URL, CacheDir: t.TempDir()}}
	if findings, warnings := a.AdviseResponse(ctx, leak, body); len(findings) != 0 || len(warnings) != 1 ||
		!strings.Contains(warnings[0], "2 Composer packages") {
		t.Errorf("down: %+v %v", findings, warnings)
	}
}
