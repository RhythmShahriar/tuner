// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/checks"
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/report"
	"github.com/RhythmShahriar/tuner/tunerconfig"
)

// leakySite serves an exposed .env and real 404s for everything else.
func leakySite(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte("<html>home</html>"))
		case "/.env":
			_, _ = w.Write([]byte("APP_NAME=Shop\nDB_PASSWORD=supersecret\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// leakPlan scans srv with the built-in leak-dotenv check, no rate limit
// and no vulnerability matching.
func leakPlan(t *testing.T, targets ...string) *Plan {
	t.Helper()
	all, err := engine.LoadChecks(checks.FS)
	if err != nil {
		t.Fatal(err)
	}
	sel, err := engine.Select(all, engine.Selector{IDs: []string{"leak-dotenv"}})
	if err != nil {
		t.Fatal(err)
	}
	return &Plan{Targets: targets, Checks: sel, Parallel: 2, Version: "test", CheckSet: "built-in",
		Engine: engine.Options{Retries: 0, Timeout: 5 * time.Second}}
}

func TestRunFailOn(t *testing.T) {
	srv := leakySite(t)
	p := leakPlan(t, srv.URL)
	var mu sync.Mutex
	var shown, done []string
	out := Run(context.Background(), p, Hooks{
		Start: func(_ int, _ string) engine.Hooks {
			return engine.Hooks{Finding: func(f engine.Finding) { mu.Lock(); shown = append(shown, f.ID); mu.Unlock() }}
		},
		Done: func(_ int, tg *Target) { mu.Lock(); done = append(done, tg.Target); mu.Unlock() },
	})
	if len(out.Reports) != 1 || out.Reports[0].CheckSet != "built-in" || !slices.Equal(shown, []string{"leak-dotenv"}) || !slices.Equal(done, []string{srv.URL}) {
		t.Fatalf("reports %+v, shown %v, done %v", out.Reports, shown, done)
	}
	if s := out.Status[0]; !s.Complete || s.VulnData != VulnOff {
		t.Errorf("status %+v", s)
	}
	for _, c := range []struct {
		failOn        engine.Severity
		confirmedOnly bool
		want          int
	}{
		{"", false, ExitOK},
		{engine.High, false, ExitFindings},
		{engine.Critical, false, ExitFindings}, // leak-dotenv is critical
		{engine.High, true, ExitFindings},      // and confirmed
	} {
		p.FailOn, p.ConfirmedOnly = c.failOn, c.confirmedOnly
		if code, why := out.Exit(p); code != c.want || why != nil {
			t.Errorf("fail-on %q: exit %d %v, want %d", c.failOn, code, why, c.want)
		}
	}
}

// A baseline and an ignore entry hide a finding from the hooks and the
// report, count it as suppressed and let --fail-on pass.
func TestRunBaselineAndIgnores(t *testing.T) {
	srv := leakySite(t)
	first := Run(context.Background(), leakPlan(t, srv.URL), Hooks{})
	// A baseline is a saved JSON report of an earlier scan.
	saved := filepath.Join(t.TempDir(), "baseline.json")
	var buf bytes.Buffer
	if err := report.JSON(&buf, first.Reports, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saved, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	base, err := report.LoadBaseline(saved)
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Plan){
		"baseline": func(p *Plan) { p.Baseline = base },
		"ignore":   func(p *Plan) { p.Ignores = []tunerconfig.Ignore{{ID: "leak-*", Path: "/.env", Reason: "demo"}} },
	} {
		p := leakPlan(t, srv.URL)
		p.FailOn = engine.Low
		edit(p)
		var shown int
		out := Run(context.Background(), p, Hooks{Start: func(int, string) engine.Hooks {
			return engine.Hooks{Finding: func(engine.Finding) { shown++ }}
		}})
		tg := out.Targets[0]
		if shown != 0 || tg.Suppressed != 1 || len(out.Reports[0].Findings) != 0 || out.Reports[0].Score != 100 {
			t.Errorf("%s: shown %d, suppressed %d, report %+v", name, shown, tg.Suppressed, out.Reports[0])
		}
		if want := len(p.Ignores); tg.Ignored != want {
			t.Errorf("%s: ignored %d, want %d", name, tg.Ignored, want)
		}
		if want := 1 - len(p.Ignores); out.Reports[0].Baselined != want {
			t.Errorf("%s: report baselined %d, want %d", name, out.Reports[0].Baselined, want)
		}
		if code, _ := out.Exit(p); code != ExitOK {
			t.Errorf("%s: exit %d", name, code)
		}
	}
}

// fakeScan returns a result for every target; "slow" waits for the run
// to stop and returns what it has with the context's error.
func fakeScan(ctx context.Context, _ *engine.Scanner, target string, _ engine.Hooks) (*engine.Result, error) {
	res := &engine.Result{Target: target, Score: 100}
	switch target {
	case "slow":
		<-ctx.Done()
		return res, ctx.Err()
	case "down":
		return nil, errors.New("can't reach down")
	case "panic":
		panic("boom")
	}
	return res, nil
}

func TestRunPartialAndFailedTargets(t *testing.T) {
	p := &Plan{Targets: []string{"ok", "slow"}, Parallel: 2, MaxTime: 50 * time.Millisecond, FailOn: engine.High, Scan: fakeScan}
	out := Run(context.Background(), p, Hooks{})
	if len(out.Reports) != 2 || out.Canceled {
		t.Fatalf("reports %d, canceled %v", len(out.Reports), out.Canceled)
	}
	if s := out.Status[1]; s.Complete || s.StoppedBy != "max-time" {
		t.Errorf("slow status %+v", s)
	}
	code, why := out.Exit(p)
	if code != ExitError || len(why) != 1 || !strings.Contains(why[0], "slow: the scan is incomplete (stopped by --max-time), so --fail-on high can't pass it") {
		t.Errorf("partial: exit %d %q", code, why)
	}
	p.AllowPartial = true
	if code, why := out.Exit(p); code != ExitError || why != nil {
		t.Errorf("--allow-partial: exit %d %q (the max-time error still fails the target)", code, why)
	}

	// A target that can't be scanned fails the run; a panic stays in its
	// target and becomes an InternalError.
	p = &Plan{Targets: []string{"ok", "down", "panic"}, Scan: fakeScan}
	out = Run(context.Background(), p, Hooks{})
	var ie InternalError
	if len(out.Reports) != 1 || !out.Targets[1].Failed() || !errors.As(out.Targets[2].Err, &ie) || len(ie.Stack) == 0 ||
		ie.Error() != "internal error (please report): boom" {
		t.Fatalf("targets %+v", out.Targets)
	}
	if code, _ := out.Exit(p); code != ExitError {
		t.Errorf("failed target: exit %d", code)
	}
	p.FailOn = engine.Info
	if code, _ := out.Exit(p); code != ExitError {
		t.Errorf("failed target with --fail-on and no findings: exit %d", code)
	}
}

// A firewall stop the engine saw reaches the target's Status and the
// report. Every finding gets its fingerprint before the baseline runs.
func TestRunEngineStopReachesReport(t *testing.T) {
	p := &Plan{Targets: []string{"https://example.com"}, Scan: func(context.Context, *engine.Scanner, string, engine.Hooks) (*engine.Result, error) {
		return &engine.Result{
			Target: "https://example.com", StoppedBy: "waf", BlockedBy: "cloudflare",
			Findings: []engine.Finding{{ID: "xmlrpc", URL: "https://example.com/xmlrpc.php", Path: "/xmlrpc.php", Severity: engine.Low}},
		}, nil
	}}
	out := Run(context.Background(), p, Hooks{})
	want := Status{Complete: false, StoppedBy: "waf", BlockedBy: "cloudflare", VulnData: VulnOff}
	if out.Targets[0].Status != want || out.Status[0] != want {
		t.Errorf("status %+v, want %+v", out.Targets[0].Status, want)
	}
	if got := out.Reports[0].Status(); got != report.Status(want) {
		t.Errorf("report status %+v, want %+v", got, want)
	}
	f := out.Reports[0].Findings[0]
	if f.Fingerprint == "" || f.Fingerprint != report.Fingerprint(f, "") {
		t.Errorf("fingerprint %q", f.Fingerprint)
	}
}

// A local scan's own vulnerability status (its Composer match) counts:
// the worse of it and the advisor's wins.
func TestRunResultVulnData(t *testing.T) {
	for _, c := range []struct{ res, want string }{{"partial", VulnPartial}, {"ok", VulnOK}, {"", VulnOff}} {
		p := &Plan{Targets: []string{"/srv/site"}, Scan: func(context.Context, *engine.Scanner, string, engine.Hooks) (*engine.Result, error) {
			return &engine.Result{Target: "/srv/site", VulnData: c.res}, nil
		}}
		if got := Run(context.Background(), p, Hooks{}).Status[0].VulnData; got != c.want {
			t.Errorf("result %q: vuln data %q, want %q", c.res, got, c.want)
		}
	}
}

func TestRunCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Plan{Targets: []string{"ok", "slow"}, Parallel: 2, Scan: fakeScan}
	out := Run(ctx, p, Hooks{Done: func(i int, _ *Target) {
		if i == 0 {
			cancel()
		}
	}})
	if !out.Canceled || out.Targets[1].Failed() || out.Status[1].StoppedBy != "interrupted" {
		t.Fatalf("outcome %+v", out)
	}
	if code, why := out.Exit(p); code != ExitCanceled || !slices.Equal(why, []string{"scan canceled; results are partial"}) {
		t.Errorf("exit %d %q", code, why)
	}
}

// An advisor that was never asked leaves the data missing, which --fail-on
// can't call clean unless AllowMissingVulns says so.
func TestRunMissingVulnData(t *testing.T) {
	p := &Plan{Targets: []string{"ok"}, Scan: fakeScan, FailOn: engine.High,
		Engine: engine.Options{Advisor: TrackVulns(nil)}}
	out := Run(context.Background(), p, Hooks{})
	if out.Status[0].VulnData != VulnMissing {
		t.Fatalf("status %+v", out.Status[0])
	}
	if code, why := out.Exit(p); code != ExitError || len(why) != 1 || !strings.Contains(why[0], "ok: no vulnerability data, so --fail-on high can't pass it") {
		t.Errorf("exit %d %q", code, why)
	}
	p.AllowMissingVulns = true
	if code, _ := out.Exit(p); code != ExitOK {
		t.Errorf("--allow-missing-vulns: exit %d", code)
	}
}

// Fast targets get their own scanner, built with FastRate.
func TestRunFastTargets(t *testing.T) {
	var mu sync.Mutex
	used := map[string]*engine.Scanner{}
	p := &Plan{Targets: []string{"a", "b", "local"}, Fast: map[string]bool{"local": true}, FastRate: 50, Engine: engine.Options{Rate: 5},
		Scan: func(ctx context.Context, s *engine.Scanner, target string, h engine.Hooks) (*engine.Result, error) {
			mu.Lock()
			used[target] = s
			mu.Unlock()
			return fakeScan(ctx, s, target, h)
		}}
	Run(context.Background(), p, Hooks{})
	if used["a"] != used["b"] || used["a"] == used["local"] || used["local"] == nil {
		t.Errorf("scanners %v", used)
	}
}

// A firewall challenge leaves a scan with no findings that proves nothing,
// so FailOn fails it unless AllowPartial says that's fine.
func TestExitBlockedScan(t *testing.T) {
	blocked := Status{Complete: false, StoppedBy: "waf", BlockedBy: "cloudflare", VulnData: VulnOK}
	out := &Outcome{
		Targets: []Target{{Target: "https://example.com/"}},
		Reports: []report.Report{{Result: &engine.Result{Target: "https://example.com/"}}},
		Status:  []Status{blocked},
	}
	for _, c := range []struct {
		allow bool
		want  int
	}{{false, ExitError}, {true, ExitOK}} {
		p := &Plan{FailOn: engine.High, AllowPartial: c.allow}
		got, why := out.Exit(p)
		if got != c.want {
			t.Errorf("AllowPartial %v: exit %d, want %d", c.allow, got, c.want)
		}
		if !c.allow && (len(why) != 1 || !strings.Contains(why[0], "https://example.com/: the scan is incomplete (blocked by Cloudflare challenge)")) {
			t.Errorf("why %q", why)
		}
	}
	// Without FailOn a partial scan keeps its exit code.
	if got, _ := out.Exit(&Plan{}); got != ExitOK {
		t.Errorf("no FailOn: exit %d", got)
	}
}

func TestGateWorst(t *testing.T) {
	fs := []engine.Finding{{Severity: engine.Critical, Confidence: "low"}, {Severity: engine.Medium}}
	if w := GateWorst(fs, false); w != engine.Critical {
		t.Errorf("every finding: %s", w)
	}
	if w := GateWorst(fs, true); w != engine.Medium {
		t.Errorf("confirmed only: %s", w)
	}
	if w := GateWorst(nil, false); w != "" {
		t.Errorf("none: %q", w)
	}
}

func TestVulnStatusFromWarnings(t *testing.T) {
	for _, c := range []struct {
		lookups  int
		warnings []string
		want     string
	}{
		{2, nil, VulnOK},
		{0, nil, VulnOK},
		{2, []string{"couldn't fetch vulnerability data for 2 components (plugin x: EOF)"}, VulnMissing},
		{1, []string{"vulnerability data not cached for 1 components; run once online to cache it"}, VulnMissing},
		{3, []string{"couldn't fetch vulnerability data for 1 components (plugin y: EOF)"}, VulnPartial},
		{2, []string{"used cached vulnerability data older than 24h0m0s for 1 components"}, VulnPartial},
		{2, []string{"couldn't fetch vulnerability data for many components"}, VulnMissing},
		{2, []string{"something unrelated"}, VulnOK},
	} {
		if got := vulnStatusFromWarnings(c.lookups, c.warnings); got != c.want {
			t.Errorf("%d lookups, %q: %s, want %s", c.lookups, c.warnings, got, c.want)
		}
	}
	fp := fingerprint.Result{WordPress: "6.4.1", Server: "nginx/1.25.3", Components: []fingerprint.Component{{Slug: "a"}, {Slug: "b"}}}
	fp.Tech = []string{"wordpress", "php"}
	if n := advisorLookups(fp); n != 5 {
		t.Errorf("advisorLookups: %d, want 5 (core, 2 plugins, hidden PHP, nginx)", n)
	}
	var s vulnSlot
	if s.get() != VulnMissing {
		t.Error("an advisor that never ran should leave the data missing")
	}
	s.set(VulnOK)
	s.set(VulnPartial)
	s.set(VulnOK)
	if s.get() != VulnPartial {
		t.Errorf("worst status should win, got %s", s.get())
	}
}

// Untrusted names the gate it was asked about and honors each allowance.
func TestUntrusted(t *testing.T) {
	missing := Status{Complete: true, VulnData: VulnMissing}
	partial := Status{StoppedBy: "max-time", VulnData: VulnOK}
	if why := Untrusted("https://a.example", missing, "--fail-on-new low", false, false); len(why) != 1 ||
		!strings.HasPrefix(why[0], "https://a.example: no vulnerability data, so --fail-on-new low can't pass it\n") {
		t.Errorf("missing data: %q", why)
	}
	if why := Untrusted("https://a.example", partial, "--fail-on-new low", false, false); len(why) != 1 ||
		!strings.Contains(why[0], "the scan is incomplete (stopped by --max-time), so --fail-on-new low can't pass it") {
		t.Errorf("partial: %q", why)
	}
	if why := Untrusted("https://a.example", missing, "--fail-on high", true, false); len(why) != 0 {
		t.Errorf("--allow-missing-vulns: %q", why)
	}
	if why := Untrusted("https://a.example", partial, "--fail-on high", false, true); len(why) != 0 {
		t.Errorf("--allow-partial: %q", why)
	}
	if why := Untrusted("https://a.example", Status{Complete: true, VulnData: VulnOK}, "--fail-on high", false, false); len(why) != 0 {
		t.Errorf("complete: %q", why)
	}
}

// The gate's reason uses the report notes' plain words, never the
// internal stopped_by tokens.
func TestStatusReason(t *testing.T) {
	for _, c := range []struct {
		s    Status
		want string
	}{
		{Status{StoppedBy: "budget"}, "stopped at the request budget"},
		{Status{StoppedBy: "home-status"}, "the home page did not load"},
		{Status{StoppedBy: "waf"}, "blocked by a firewall challenge"},
		{Status{StoppedBy: "waf", BlockedBy: "sucuri"}, "blocked by Sucuri challenge"},
		{Status{StoppedBy: "interrupted"}, "interrupted"},
		{Status{StoppedBy: "max-time"}, "stopped by --max-time"},
		{Status{StoppedBy: "integrity"}, "some checksums for --integrity could not be loaded"},
		{Status{}, "the scan did not finish"},
	} {
		if got := c.s.Reason(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.s, got, c.want)
		}
	}
}
