package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
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
		{"scan", "./"},
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
