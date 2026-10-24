// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/report"
)

const rawSecret = "supersecret-db-pass"

// leakySite serves an exposed .env and real 404s for everything else.
func leakySite(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte("<html>home</html>"))
		case "/.env":
			w.Write([]byte("APP_NAME=Shop\nDB_PASSWORD=" + rawSecret + "\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cleanSite(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		for k, v := range map[string]string{
			"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY",
			"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
		} {
			w.Header().Set(k, v)
		}
		w.Write([]byte("<html>home</html>"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func tuner(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // keep the first-run marker out of the real config
	if os.Getenv("XDG_CACHE_HOME") == "" {
		t.Setenv("XDG_CACHE_HOME", t.TempDir()) // and the vulnerability cache
	}
	if os.Getenv("TUNER_VULN_API") == "" {
		t.Setenv("TUNER_VULN_API", "http://127.0.0.1:1") // never reach the real APIs from tests
		t.Setenv("TUNER_WPORG_API", "http://127.0.0.1:1")
		t.Setenv("TUNER_PHPNET_API", "http://127.0.0.1:1")
	}
	if os.Getenv("TUNER_CHECKS_URL") == "" {
		t.Setenv("TUNER_CHECKS_URL", "http://127.0.0.1:1") // nor the check pack release
	}
	var out, errb bytes.Buffer
	if len(args) > 0 && args[0] == "scan" {
		args = append(args, "--rate", "0")
	}
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestScanJSON(t *testing.T) {
	srv := leakySite(t)
	code, out, errs := tuner(t, "scan", srv.URL, "--json")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var rep struct {
		Schema   string
		Score    int
		Findings []struct{ ID string }
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if rep.Schema != "rhythm-tuner/v0" || !hasFinding(rep.Findings, "leak-dotenv") || rep.Score >= 100 {
		t.Errorf("unexpected report: %+v", rep)
	}
	if strings.Contains(out, rawSecret) {
		t.Error("JSON output leaks the raw secret")
	}
}

func hasFinding(fs []struct{ ID string }, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestOutputFiles(t *testing.T) {
	srv := leakySite(t)
	dir := t.TempDir()
	for _, name := range []string{"r.sarif", "r.md", "r.json", "r.jsonl"} {
		path := filepath.Join(dir, name)
		code, out, errs := tuner(t, "scan", srv.URL, "-o", path, "--plain")
		if code != exitOK {
			t.Fatalf("%s: exit %d: %s", name, code, errs)
		}
		if !strings.Contains(out, ".env file exposed") {
			t.Errorf("%s: live view missing while writing a file:\n%s", name, out)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), rawSecret) {
			t.Errorf("%s leaks the raw secret", name)
		}
		if !strings.Contains(string(data), "leak-dotenv") {
			t.Errorf("%s has no leak-dotenv finding:\n%s", name, data)
		}
	}
	var sarif struct {
		Version string
		Runs    []struct {
			Results []struct{ RuleID, Level string }
		}
	}
	data, _ := os.ReadFile(filepath.Join(dir, "r.sarif"))
	if err := json.Unmarshal(data, &sarif); err != nil || sarif.Version != "2.1.0" || len(sarif.Runs) != 1 {
		t.Errorf("bad SARIF: %v", err)
	}
}

func TestFailOnAndBaseline(t *testing.T) {
	srv := leakySite(t)
	if code, _, _ := tuner(t, "scan", srv.URL, "--json", "--fail-on", "high"); code != exitFindings {
		t.Errorf("--fail-on high with a critical finding: exit %d, want %d", code, exitFindings)
	}
	clean := cleanSite(t)
	if code, _, errs := tuner(t, "scan", clean.URL, "--json", "--fail-on", "high"); code != exitOK {
		t.Errorf("--fail-on high on a site with only medium findings: exit %d: %s", code, errs)
	}

	base := filepath.Join(t.TempDir(), "baseline.json")
	if code, _, errs := tuner(t, "scan", srv.URL, "-o", base, "-q"); code != exitOK {
		t.Fatalf("writing baseline: exit %d: %s", code, errs)
	}
	code, out, _ := tuner(t, "scan", srv.URL, "--json", "--baseline", base, "--fail-on", "info")
	if code != exitOK || strings.Contains(out, "leak-dotenv") {
		t.Errorf("baselined findings still reported (exit %d)", code)
	}
}

func TestBatch(t *testing.T) {
	a, b := leakySite(t), cleanSite(t)
	list := filepath.Join(t.TempDir(), "sites.txt")
	os.WriteFile(list, []byte("# agency sites\n"+a.URL+"\n\n"+b.URL+"  # client B\n"+a.URL+"\n"), 0o644)
	code, out, errs := tuner(t, "scan", "-l", list, "--json")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var reps []struct{ Target string }
	if err := json.Unmarshal([]byte(out), &reps); err != nil || len(reps) != 2 {
		t.Fatalf("want 2 reports (duplicates removed), got %d: %v", len(reps), err)
	}
}

func TestUnreachableTarget(t *testing.T) {
	srv := leakySite(t)
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	code, out, errs := tuner(t, "scan", srv.URL, dead.URL, "--json")
	if code != exitError || !strings.Contains(errs, "can't reach") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if !strings.Contains(out, "leak-dotenv") {
		t.Error("the reachable target's report is missing")
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{"scan"},
		{"scan", "example.com", "--json", "--sarif"},
		{"scan", "example.com", "-H", "no colon"},
		{"scan", "./no-such-dir"},
		{"scan", "example.com", "--profile", "turbo"},
		{"scan", "example.com", "--fail-on", "urgent"},
		{"scan", "example.com", "--proxy", "ftp://x"},
		{"scan", "example.com", "-o", "report.txt"},
		{"scan", "example.com", "--id", "nope-*"},
		{"bogus"},
	}
	for _, args := range cases {
		if code, _, _ := tuner(t, args...); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
	}
}

func TestChecksCommand(t *testing.T) {
	code, out, _ := tuner(t, "checks", "--tags", "tls")
	if code != exitOK || !strings.Contains(out, "tls-cert-expired") || strings.Contains(out, "leak-dotenv") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestVulnScan(t *testing.T) {
	var apiHits atomic.Int32
	var apiDown atomic.Bool
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiHits.Add(1)
		if apiDown.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		switch r.URL.Path {
		case "/plugin/contact-form-7/":
			w.Write([]byte(`{"error":0,"data":{"name":"Contact Form 7","closed":0,"vulnerability":[{"uuid":"u1",
				"operator":{"max_version":"5.3.2","max_operator":"lt","unfixed":"0"},
				"source":[{"id":"CVE-2020-35489","name":"CVE-2020-35489","link":"https://www.cve.org/x"}],
				"impact":{"cvss3":{"score":"10.0","severity":"critical"},"kev":false}}]}}`))
		case "/plugins/info/1.2/":
			w.Write([]byte(`{"version":"6.2.3","last_updated":"2026-10-21 8:43am GMT"}`))
		default:
			w.Write([]byte(`{"error":0,"data":{"vulnerability":[]}}`))
		}
	}))
	defer api.Close()
	t.Setenv("TUNER_VULN_API", api.URL)
	t.Setenv("TUNER_WPORG_API", api.URL)
	t.Setenv("TUNER_PHPNET_API", api.URL)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	packRelease(t, packCheck, "0.2.0") // so update's check pack refresh succeeds

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<link href="/wp-content/plugins/contact-form-7/s.css?ver=5.3.1">`))
		case "/wp-content/plugins/contact-form-7/readme.txt":
			w.Write([]byte("Stable tag: 5.3.1\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()

	code, out, errs := tuner(t, "scan", site.URL, "--md")
	if code != exitOK || !strings.Contains(out, "contact-form-7 5.3.1: 1 known vulnerability") ||
		!strings.Contains(out, "CVE-2020-35489") || !strings.Contains(out, "WPVulnerability") {
		t.Fatalf("exit %d, stderr %s\n%s", code, errs, out)
	}

	// Cached now: offline works with the API down, and makes no requests.
	apiDown.Store(true)
	hits := apiHits.Load()
	code, out, _ = tuner(t, "scan", site.URL, "--json", "--offline", "--id", "vuln-*")
	if code != exitOK || !strings.Contains(out, "vuln-plugin-contact-form-7") || strings.Contains(out, "hdr-") {
		t.Errorf("offline --id vuln-*: exit %d\n%s", code, out)
	}
	if apiHits.Load() != hits {
		t.Error("--offline made requests")
	}

	// update keeps cached copies when the API fails, and says so.
	if code, out, _ := tuner(t, "update"); code != exitError || !strings.Contains(out, "failed; cached copies kept") {
		t.Errorf("update with API down: exit %d\n%s", code, out)
	}
	apiDown.Store(false)
	if code, out, _ := tuner(t, "update"); code != exitOK || !strings.Contains(out, "Refreshed 2 vulnerability records") {
		t.Errorf("update: exit %d\n%s", code, out)
	}
	if code, _, _ := tuner(t, "scan", site.URL, "--json", "--no-vulns", "--id", "vuln-*"); code != exitUsage {
		t.Errorf("--no-vulns with only vuln ids should be a usage error, got %d", code)
	}
}

func TestUpdateNotice(t *testing.T) {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name":"v9.0.0","assets":[]}`))
	}))
	defer gh.Close()
	t.Setenv("RHYTHM_GITHUB_API", gh.URL)
	t.Setenv("CI", "")
	t.Setenv("RHYTHM_NO_UPDATE_CHECK", "")
	old := version
	version = "0.1.0"
	defer func() { version = old }()

	_, _, errs := tuner(t, "scan", cleanSite(t).URL, "--plain")
	if !strings.Contains(errs, "0.1.0 → 9.0.0") || !strings.Contains(errs, "rhythm update") {
		t.Errorf("no update notice in stderr:\n%s", errs)
	}
	t.Setenv("RHYTHM_NO_UPDATE_CHECK", "1")
	if _, _, errs := tuner(t, "scan", cleanSite(t).URL, "--plain"); strings.Contains(errs, "new release") {
		t.Error("RHYTHM_NO_UPDATE_CHECK ignored")
	}
}

func TestChecksHelpAndFooter(t *testing.T) {
	code, out, _ := tuner(t, "checks", "--help")
	if code != exitOK || !strings.Contains(out, `--profile <name>     quick, default or deep (default "deep")`) {
		t.Errorf("checks --help: exit %d\n%s", code, out)
	}
	if code, _, errs := tuner(t, "checks", "--bogus"); code != exitUsage || !strings.Contains(errs, "Usage:") {
		t.Errorf("checks --bogus: exit %d\n%s", code, errs)
	}
	_, out, _ = tuner(t, "checks", "--id", "leak-dotenv", "--no-check-updates")
	if !strings.Contains(out, "1 check, plus") || !strings.Contains(out, "which scans skip with --no-vulns") {
		t.Errorf("footer:\n%s", out)
	}
}

func TestKnownExploitedTagSelectsVulnMatching(t *testing.T) {
	if code, _, errs := tuner(t, "scan", cleanSite(t).URL, "--tags", "known-exploited", "--json"); code != exitOK {
		t.Errorf("--tags known-exploited: exit %d: %s", code, errs)
	}
}

// A batch gives an array even when only one site could be scanned, so
// scripts can always loop over the result.
func TestBatchJSONStaysArray(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	_, out, _ := tuner(t, "scan", cleanSite(t).URL, dead.URL, "--json")
	var reps []struct{ Target string }
	if err := json.Unmarshal([]byte(out), &reps); err != nil || len(reps) != 1 {
		t.Errorf("want an array with the one reachable site, got %v:\n%.200s", err, out)
	}
}

func TestClassifyTarget(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, d := range []string{"example.com", "wordpress", "sites/shop"} {
		os.MkdirAll(d, 0o755)
	}
	cases := []struct {
		target    string
		local     bool
		ambiguous bool
	}{
		{"example.com", false, true},
		{"wordpress", false, true},
		{"./example.com", true, false},
		{"../example.com", true, false},
		{".", true, false},
		{"..", true, false},
		{"~", true, false},
		{"~/sites/shop", true, false},
		{"/var/www/example.com", true, false},
		{`C:\inetpub\wwwroot`, true, false},
		{"c:/sites", true, false},
		{`.\example.com`, true, false},
		{"sites/shop", true, false},
		{"sites/missing", true, false}, // a path, so local.Root reports it missing
		{"https://example.com", false, false},
		{"http://example.com/blog", false, false},
		{"example.org", false, false},       // no folder by that name
		{"example.org/blog", false, false},  // host and path
		{"localhost:8080/wp", false, false}, // host with a port
		{"example.com/blog", false, false},  // no folder by that path
		{"127.0.0.1:20220", false, false},   // not a drive letter
	}
	for _, c := range cases {
		local, err := classifyTarget(c.target)
		if local != c.local || (err != nil) != c.ambiguous {
			t.Errorf("%s: local %v, err %v; want local %v, ambiguous %v", c.target, local, err, c.local, c.ambiguous)
		}
	}
}

// A folder named like the site must not turn a remote scan into a local
// one, or the other way round.
func TestFolderNamedLikeHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("folder names can't hold a colon")
	}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	t.Chdir(t.TempDir())
	for _, d := range []string{host, "example.com"} {
		os.MkdirAll(filepath.Join(d, "wp-includes"), 0o755)
		os.WriteFile(filepath.Join(d, "wp-includes", "version.php"), []byte("<?php $wp_version = '6.4.1';"), 0o600)
	}

	for _, target := range []string{"example.com", host} {
		code, _, errs := tuner(t, "scan", target, "--json")
		want := target + " is both a folder here and a hostname; use ./" + target + " or https://" + target
		if code != exitUsage || !strings.Contains(errs, want) {
			t.Errorf("%s: exit %d, stderr %q", target, code, errs)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("an ambiguous target sent %d requests", hits.Load())
	}

	code, out, errs := tuner(t, "scan", "./"+host, "--json", "--no-vulns", "--php", "/nonexistent/php")
	if code != exitOK || !strings.Contains(out, `"wordpress_version": "6.4.1"`) || hits.Load() != 0 {
		t.Errorf("./%s: exit %d, %d requests, stderr %s\n%.300s", host, code, hits.Load(), errs, out)
	}
	if code, _, errs := tuner(t, "scan", srv.URL, "--json", "--no-vulns"); code != exitOK || hits.Load() == 0 {
		t.Errorf("%s: exit %d, %d requests: %s", srv.URL, code, hits.Load(), errs)
	}
	p, err := planScan([]string{"https://example.com", "--no-vulns", "--no-check-updates"}, nil)
	if err != nil || isLocalPath(p.targets[0]) {
		t.Errorf("https://example.com: %v", err)
	}
}

// hangingSite answers the home page, then holds every other request until
// the test ends, so a scan is reliably still running when the test stops it.
func hangingSite(t *testing.T) (srv *httptest.Server, started <-chan struct{}) {
	t.Helper()
	release, start := make(chan struct{}), make(chan struct{})
	var once sync.Once
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte("<html>home</html>"))
			return
		}
		once.Do(func() { close(start) })
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs first
	return srv, start
}

const oldReport = `{"previous": "report"}`

func writeOld(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte(oldReport), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertOld(t *testing.T, path string) {
	t.Helper()
	if data, err := os.ReadFile(path); err != nil || string(data) != oldReport {
		t.Errorf("previous report changed: %q, %v", data, err)
	}
}

func TestReportReplacedOnlyWhenComplete(t *testing.T) {
	path := writeOld(t)
	if code, _, errs := tuner(t, "scan", leakySite(t).URL, "-o", path, "-q"); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	data, _ := os.ReadFile(path)
	fi, _ := os.Stat(path)
	if !strings.Contains(string(data), "leak-dotenv") || fi.Mode().Perm() != 0o640 {
		t.Errorf("report not replaced (mode %v):\n%.200s", fi.Mode(), data)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".*.tmp")); len(left) > 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

func TestReportKeptWhenEveryTargetFails(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	for _, name := range []string{"report.json", "report.jsonl"} {
		path := filepath.Join(t.TempDir(), name)
		os.WriteFile(path, []byte(oldReport), 0o600)
		code, _, errs := tuner(t, "scan", dead.URL, "-o", path, "--retries", "0")
		if code != exitError || !strings.Contains(errs, "rhythm tuner: no report written: every target failed") {
			t.Errorf("%s: exit %d, stderr %q", name, code, errs)
		}
		if data, _ := os.ReadFile(path); string(data) != oldReport {
			t.Errorf("%s replaced: %q", name, data)
		}
		if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".*.tmp")); len(left) > 0 {
			t.Errorf("temporary files left: %v", left)
		}
	}
}

func TestReportKeptOnCancel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sends SIGINT to the test process")
	}
	srv, started := hangingSite(t)
	path := writeOld(t)
	go func() {
		<-started
		syscall.Kill(os.Getpid(), syscall.SIGINT) // execute catches it as a cancel
	}()
	code, _, errs := tuner(t, "scan", srv.URL, "-o", path, "--jsonl")
	if code != exitCanceled || !strings.Contains(errs, "no report written: scan canceled") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	assertOld(t, path)
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".*.tmp")); len(left) > 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

// TestHelperProcess runs the CLI in a child process for tests that kill it.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("TUNER_HELPER_ARGS") == "" {
		t.Skip("only runs as a child process")
	}
	stderr := io.Discard
	if os.Getenv("TUNER_HELPER_STDERR") != "" {
		stderr = os.Stderr
	}
	if os.Getenv("TUNER_HELPER_HANG") != "" {
		// A target stuck where cancellation can't reach it, like a read
		// from a FIFO.
		scanOne = func(*scanPlan, context.Context, *engine.Scanner, string, engine.Hooks) (*engine.Result, error) {
			fmt.Fprintln(os.Stderr, "scan blocked")
			time.Sleep(time.Hour)
			return nil, nil
		}
	}
	os.Exit(run(strings.Split(os.Getenv("TUNER_HELPER_ARGS"), "\n"), io.Discard, stderr))
}

func TestSecondInterruptQuits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sends SIGINT to a child process")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(),
		"TUNER_HELPER_ARGS="+strings.Join([]string{"scan", t.TempDir(), "--no-vulns", "--no-check-updates"}, "\n"),
		"TUNER_HELPER_HANG=1", "TUNER_HELPER_STDERR=1", "RHYTHM_OFFLINE=1",
		"XDG_CONFIG_HOME="+t.TempDir(), "XDG_CACHE_HOME="+t.TempDir())
	pipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(pipe)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	waitFor := func(want string) {
		t.Helper()
		deadline := time.After(20 * time.Second)
		for {
			select {
			case line, ok := <-lines:
				if !ok {
					t.Fatalf("the child exited before printing %q", want)
				}
				if strings.Contains(line, want) {
					return
				}
			case <-deadline:
				t.Fatalf("no %q from the child", want)
			}
		}
	}

	waitFor("scan blocked")
	cmd.Process.Signal(os.Interrupt)
	waitFor("rhythm tuner: stopping... press Ctrl+C again to quit now")
	cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() {
		for range lines { // drain, so the child never blocks on a full pipe
		}
		done <- cmd.Wait()
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the second Ctrl+C did not end the scan within 1s")
	}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGINT {
		t.Errorf("want the child ended by SIGINT, got %v", cmd.ProcessState)
	}
}

func TestPanicInOneTarget(t *testing.T) {
	good, bad := leakySite(t), cleanSite(t)
	orig := scanOne
	defer func() { scanOne = orig }()
	scanOne = func(p *scanPlan, ctx context.Context, s *engine.Scanner, target string, h engine.Hooks) (*engine.Result, error) {
		if target == bad.URL {
			panic("boom")
		}
		return orig(p, ctx, s, target, h)
	}
	code, out, errs := tuner(t, "scan", good.URL, bad.URL, "--json", "--no-vulns")
	var reps []struct{ Target string }
	if err := json.Unmarshal([]byte(out), &reps); err != nil || len(reps) != 1 {
		t.Fatalf("want the good target's report: %v\n%s", err, out)
	}
	if code != exitError || !strings.Contains(errs, "rhythm tuner: "+bad.URL+": internal error (please report): boom") ||
		strings.Contains(errs, "goroutine ") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if _, _, errs := tuner(t, "scan", bad.URL, "--json", "--no-vulns", "-v"); !strings.Contains(errs, "goroutine ") {
		t.Errorf("-v should print the stack:\n%s", errs)
	}
}

func TestReportSurvivesSIGKILL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SIGKILL")
	}
	srv, started := hangingSite(t)
	path := writeOld(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(),
		"TUNER_HELPER_ARGS="+strings.Join([]string{"scan", srv.URL, "-o", path, "--rate", "0", "--no-vulns", "--no-check-updates"}, "\n"),
		"XDG_CONFIG_HOME="+t.TempDir(), "XDG_CACHE_HOME="+t.TempDir())
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(20 * time.Second):
		cmd.Process.Kill()
		t.Fatal("the child never started scanning")
	}
	cmd.Process.Kill()
	cmd.Wait()
	assertOld(t, path) // a stray temporary file may stay behind; the report is intact
}

func TestReportFolderNotWritable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions that apply to this user")
	}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	dir := t.TempDir()
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	code, _, errs := tuner(t, "scan", srv.URL, "-o", filepath.Join(dir, "r.json"))
	if code != exitError || !strings.Contains(errs, "can't write the report to "+dir+": permission denied") || hits.Load() != 0 {
		t.Errorf("exit %d, %d requests, stderr %q", code, hits.Load(), errs)
	}
	if code, _, errs := tuner(t, "scan", srv.URL, "--json", "-o", t.TempDir()); code != exitError || !strings.Contains(errs, "it is a directory") {
		t.Errorf("-o a directory: exit %d, stderr %q", code, errs)
	}
}

func TestTimeoutMessages(t *testing.T) {
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(hang.Close)
	_, _, errs := tuner(t, "scan", hang.URL, "--timeout", "1s", "--retries", "0", "--no-vulns", "--plain")
	if !strings.Contains(errs, "no response within 1s (tried once)") || strings.Contains(errs, "--max-time;") {
		t.Errorf("--timeout: %q", errs)
	}
	_, _, errs = tuner(t, "scan", hang.URL, "--timeout", "5s", "--max-time", "300ms", "--no-vulns", "--plain")
	if !strings.Contains(errs, "stopped by --max-time; results are partial") {
		t.Errorf("--max-time: %q", errs)
	}
}

func TestReadTargets(t *testing.T) {
	got, err := readTargets(strings.NewReader("\uFEFFa.example\r\n# note\r\n\r\nb.example  # client\r\n"), "sites.txt")
	if err != nil || strings.Join(got, ",") != "a.example,b.example" {
		t.Errorf("BOM and CRLF: %q, %v", got, err)
	}
	for _, c := range []struct {
		line int
		long int
	}{{2, 70_000}, {3, 2 << 20}} {
		in := "a.example\n" + strings.Repeat("\n", c.line-2) + strings.Repeat("x", c.long) + "\nb.example\n"
		path := filepath.Join(t.TempDir(), "sites.txt")
		os.WriteFile(path, []byte(in), 0o600)
		code, _, errs := tuner(t, "scan", "-l", path, "--json")
		if want := fmt.Sprintf("%s line %d:", path, c.line); code != exitUsage || !strings.Contains(errs, want) {
			t.Errorf("%d-byte line: exit %d, stderr %.200q, want %q", c.long, code, errs, want)
		}
	}
}

func TestJSONLWriteError(t *testing.T) {
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skip("no /dev/full")
	}
	defer full.Close()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("TUNER_CHECKS_URL", "http://127.0.0.1:1")
	var errb bytes.Buffer
	code := run([]string{"scan", leakySite(t).URL, "--jsonl", "--no-vulns", "--rate", "0"}, full, &errb)
	if code != exitError || !strings.Contains(errb.String(), "writing report:") {
		t.Errorf("exit %d, stderr %q", code, errb.String())
	}
}

func TestBadHeaderValues(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	for _, args := range [][]string{
		{"-H", "X-Test: a\r\nInjected: 1"},
		{"-H", "X-Test: a\nb"},
		{"-H", "X(Test): a"},
		{"-A", "tuner\r\nX-Injected: 1"},
		{"--cookie", "a=b\r\nX: y"},
	} {
		code, _, errs := tuner(t, append([]string{"scan", srv.URL}, args...)...)
		if code != exitUsage || !strings.Contains(errs, "bad ") {
			t.Errorf("%q: exit %d, stderr %q", args, code, errs)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("bad headers still sent %d requests", hits.Load())
	}
	if code, _, errs := tuner(t, "scan", srv.URL, "-H", "X-Test: a\tb", "--no-vulns", "--json"); code != exitOK {
		t.Errorf("a tab is a valid header value: exit %d: %s", code, errs)
	}
}

func TestFlagErrorsAreUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "example.com", "--bogus"},
		{"scan", "example.com", "--rate", "fast"},
		{"scan", "example.com", "--timeout"},
	} {
		if code, _, _ := tuner(t, args...); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
	}
}

func TestOfflineSkipsUpdateCheck(t *testing.T) {
	var hits atomic.Int32
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{"tag_name":"v9.0.0","assets":[]}`))
	}))
	defer gh.Close()
	t.Setenv("RHYTHM_GITHUB_API", gh.URL)
	t.Setenv("CI", "")
	t.Setenv("RHYTHM_NO_UPDATE_CHECK", "")
	old := version
	version = "0.1.0"
	defer func() { version = old }()

	site := cleanSite(t).URL
	if _, _, errs := tuner(t, "scan", site, "--plain", "--offline"); strings.Contains(errs, "new release") {
		t.Errorf("--offline printed an update notice:\n%s", errs)
	}
	t.Setenv("RHYTHM_OFFLINE", "1")
	if _, _, errs := tuner(t, "scan", site, "--plain"); strings.Contains(errs, "new release") {
		t.Errorf("RHYTHM_OFFLINE printed an update notice:\n%s", errs)
	}
	if hits.Load() != 0 {
		t.Errorf("offline runs asked GitHub %d times", hits.Load())
	}
	t.Setenv("RHYTHM_OFFLINE", "0")
	if _, _, errs := tuner(t, "scan", site, "--plain"); !strings.Contains(errs, "new release") {
		t.Errorf("RHYTHM_OFFLINE=0 should still check:\n%s", errs)
	}
}

func TestDuplicateTargetForms(t *testing.T) {
	var homes atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			homes.Add(1)
			w.Write([]byte("<html>home</html>"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	code, out, errs := tuner(t, "scan", host, srv.URL+"/", "HTTPS://"+strings.ToUpper(host), "-k", "--no-vulns", "--json")
	if code != exitOK || !strings.HasPrefix(strings.TrimSpace(out), "{") || homes.Load() != 1 {
		t.Errorf("exit %d, %d home requests, stderr %s\n%.100s", code, homes.Load(), errs, out)
	}

	for _, c := range [][2]string{
		{"example.com", "https://example.com/"},
		{"Example.COM", "https://example.com:443"},
		{"http://example.com:80/blog/", "http://example.com/blog"},
		{"[::1]:443", "https://[::1]"},
	} {
		if a, b := targetKey(c[0]), targetKey(c[1]); a != b {
			t.Errorf("%s and %s differ: %s, %s", c[0], c[1], a, b)
		}
	}
	for _, c := range [][2]string{
		{"example.com", "http://example.com"},
		{"example.com", "example.com/blog"},
		{"example.com:8443", "example.com"},
	} {
		if targetKey(c[0]) == targetKey(c[1]) {
			t.Errorf("%s and %s should stay apart", c[0], c[1])
		}
	}
}

// pluginSite looks like WordPress with contact-form-7 5.3.1, so a scan
// asks the vulnerability API about it.
func pluginSite(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<link href="/wp-content/plugins/contact-form-7/s.css?ver=5.3.1">`))
		case "/wp-content/plugins/contact-form-7/readme.txt":
			w.Write([]byte("Stable tag: 5.3.1\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

type statusReport struct {
	Complete  *bool  `json:"complete"`
	StoppedBy string `json:"stopped_by"`
	VulnData  string `json:"vuln_data"`
}

func TestFailOnNeedsVulnData(t *testing.T) {
	// The API accepts each connection and drops it without an answer.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			conn.Close()
		}
	}))
	defer api.Close()
	t.Setenv("TUNER_VULN_API", api.URL)
	t.Setenv("TUNER_WPORG_API", api.URL)
	t.Setenv("TUNER_PHPNET_API", api.URL)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	site := pluginSite(t).URL

	code, out, errs := tuner(t, "scan", site, "--json", "--fail-on", "high")
	var rep statusReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if code != exitError || rep.VulnData != "missing" || rep.Complete == nil || !*rep.Complete ||
		!strings.Contains(errs, "no vulnerability data, so --fail-on high can't pass it") ||
		!strings.Contains(errs, "--allow-missing-vulns") {
		t.Errorf("exit %d, %+v, stderr %q", code, rep, errs)
	}
	if code, _, errs := tuner(t, "scan", site, "--json", "--fail-on", "high", "--allow-missing-vulns"); code != exitOK {
		t.Errorf("--allow-missing-vulns: exit %d: %s", code, errs)
	}
	if code, _, errs := tuner(t, "scan", site, "--json"); code != exitOK {
		t.Errorf("no --fail-on: exit %d: %s", code, errs)
	}
	code, out, _ = tuner(t, "scan", site, "--json", "--fail-on", "high", "--no-vulns")
	if json.Unmarshal([]byte(out), &rep); code != exitOK || rep.VulnData != "off" {
		t.Errorf("--no-vulns: exit %d, vuln_data %q", code, rep.VulnData)
	}
}

func TestVulnDataOK(t *testing.T) {
	states, err := os.ReadFile("../../vulns/testdata/phpnet-states.json")
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases/states.php" {
			w.Write(states)
			return
		}
		w.Write([]byte(`{"error":0,"data":{"vulnerability":[]}}`))
	}))
	defer api.Close()
	t.Setenv("TUNER_VULN_API", api.URL)
	t.Setenv("TUNER_WPORG_API", api.URL)
	t.Setenv("TUNER_PHPNET_API", api.URL)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	code, out, errs := tuner(t, "scan", pluginSite(t).URL, "--json", "--fail-on", "critical")
	var rep statusReport
	if json.Unmarshal([]byte(out), &rep); code != exitOK || rep.VulnData != "ok" {
		t.Errorf("exit %d, vuln_data %q, stderr %s\n%s", code, rep.VulnData, errs, out)
	}
}

func TestInterruptedReportSaysSo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sends SIGINT to the test process")
	}
	srv, started := hangingSite(t)
	go func() {
		<-started
		syscall.Kill(os.Getpid(), syscall.SIGINT)
	}()
	code, out, errs := tuner(t, "scan", srv.URL, "--json", "--no-vulns")
	var rep statusReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if code != exitCanceled || rep.Complete == nil || *rep.Complete || rep.StoppedBy != "interrupted" {
		t.Errorf("exit %d, %+v, stderr %q", code, rep, errs)
	}
}

func TestMaxTimeReportSaysSo(t *testing.T) {
	srv, _ := hangingSite(t)
	code, out, errs := tuner(t, "scan", srv.URL, "--json", "--no-vulns", "--max-time", "500ms", "--fail-on", "high")
	var rep statusReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if code != exitError || *rep.Complete || rep.StoppedBy != "max-time" ||
		!strings.Contains(errs, "the scan is incomplete (stopped by --max-time)") {
		t.Errorf("exit %d, %+v, stderr %q", code, rep, errs)
	}
}

// A firewall challenge leaves a scan with no findings that proves nothing,
// so --fail-on fails it unless --allow-partial says that's fine.
func TestFailOnBlockedScan(t *testing.T) {
	reports := []report.Report{{Result: &engine.Result{Target: "https://example.com/"}}}
	blocked := runStatus{Complete: false, StoppedBy: "waf", BlockedBy: "Cloudflare challenge", VulnData: vulnOK}
	for _, c := range []struct {
		allow bool
		want  int
	}{{false, exitError}, {true, exitOK}} {
		p := &scanPlan{failOn: engine.High}
		p.o.allowPartial = c.allow
		p.write.Status = []runStatus{blocked}
		var errb bytes.Buffer
		got := scanExit(context.Background(), p, reports, []string{""}, &errb)
		if got != c.want {
			t.Errorf("--allow-partial %v: exit %d, want %d", c.allow, got, c.want)
		}
		if !c.allow && !strings.Contains(errb.String(), "https://example.com/: the scan is incomplete (blocked by Cloudflare challenge)") {
			t.Errorf("stderr %q", errb.String())
		}
	}
	// Without --fail-on a partial scan keeps its exit code.
	p := &scanPlan{}
	p.write.Status = []runStatus{blocked}
	if got := scanExit(context.Background(), p, reports, []string{""}, io.Discard); got != exitOK {
		t.Errorf("no --fail-on: exit %d", got)
	}
}

func TestVulnStatusFromWarnings(t *testing.T) {
	for _, c := range []struct {
		lookups  int
		warnings []string
		want     string
	}{
		{2, nil, vulnOK},
		{0, nil, vulnOK},
		{2, []string{"couldn't fetch vulnerability data for 2 components (plugin x: EOF)"}, vulnMissing},
		{1, []string{"vulnerability data not cached for 1 components; run once online to cache it"}, vulnMissing},
		{3, []string{"couldn't fetch vulnerability data for 1 components (plugin y: EOF)"}, vulnPartial},
		{2, []string{"used cached vulnerability data older than 24h0m0s for 1 components"}, vulnPartial},
		{2, []string{"couldn't fetch vulnerability data for many components"}, vulnMissing},
		{2, []string{"something unrelated"}, vulnOK},
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
	if s.get() != vulnMissing {
		t.Error("an advisor that never ran should leave the data missing")
	}
	s.set(vulnOK)
	s.set(vulnPartial)
	s.set(vulnOK)
	if s.get() != vulnPartial {
		t.Errorf("worst status should win, got %s", s.get())
	}
}

func TestHTTPClientUsesProxy(t *testing.T) {
	var mu sync.Mutex
	var got struct{ url, ua string }
	seen := func() struct{ url, ua string } { mu.Lock(); defer mu.Unlock(); return got }
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got.url, got.ua = r.URL.String(), r.UserAgent() // a proxy sees the absolute URL
		mu.Unlock()
		w.Write([]byte("ok"))
	}))
	defer proxy.Close()
	u, _ := url.Parse(proxy.URL)
	c := httpClient("rhythm-tuner/test", u, 5*time.Second)
	resp, err := c.Get("http://vulns.example.invalid/plugin/x/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if g := seen(); g.url != "http://vulns.example.invalid/plugin/x/" || g.ua != "rhythm-tuner/test" || c.Timeout != 5*time.Second {
		t.Errorf("proxy saw %+v, timeout %v", g, c.Timeout)
	}

	// A caller's own User-Agent wins and its request is left as it was.
	req, _ := http.NewRequest(http.MethodGet, "http://vulns.example.invalid/", nil)
	req.Header.Set("User-Agent", "custom")
	if resp, err := c.Do(req); err == nil {
		resp.Body.Close()
	}
	if g := seen(); g.ua != "custom" {
		t.Errorf("User-Agent %q, want custom", g.ua)
	}
	req, _ = http.NewRequest(http.MethodGet, "http://vulns.example.invalid/", nil)
	if resp, err := c.Do(req); err == nil {
		resp.Body.Close()
	}
	if req.Header.Get("User-Agent") != "" {
		t.Error("the default User-Agent changed the caller's request")
	}
}

// The help and README promise only what the code does today. Each claim
// listed here was too strong; the limits stay stated until the fix lands.
func TestHelpAndReadmeClaims(t *testing.T) {
	var help bytes.Buffer
	usage(&help)
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		text    string
		without []string
		with    []string
	}{
		"help": {help.String(),
			[]string{"refresh the check pack and vulnerability data now"},
			[]string{"also after\n                           the home page redirects to another host", "(checksummed, not signed;",
				"Never runs\n                           site code", "--allow-missing-vulns", "--allow-partial"}},
		"README": {string(readme),
			[]string{"always masked", "which are [signed with cosign]", "Tuner is non-intrusive (plain GET requests",
				"Tuner sends ordinary, rate-limited GET requests"},
			[]string{"Nothing checks the signature for you yet", "also after the home page redirects to another host",
				"Tuner does not yet refuse other methods", "The check pack is checksummed, not signed",
				"echo \"$HOME/.local/bin\" >> \"$GITHUB_PATH\""}},
	} {
		for _, s := range c.without {
			if strings.Contains(c.text, s) {
				t.Errorf("%s still says %q", name, s)
			}
		}
		for _, s := range c.with {
			if !strings.Contains(c.text, s) {
				t.Errorf("%s lacks %q", name, s)
			}
		}
	}
}
