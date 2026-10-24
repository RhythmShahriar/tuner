// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/report"
)

// twoSites is a batch scan of two sites; a.test sends markup in its
// Server header.
func twoSites() []report.Report {
	a := report.New(&engine.Result{Target: "https://a.test", Score: 70, Checks: 40, Requests: 61,
		Fingerprint: fingerprint.Result{Tech: []string{"wordpress"}, Server: `<img src=x onerror=alert(1)>`},
		Findings: []engine.Finding{
			finding("leak-git-config", "/.git/config", engine.High), finding("xmlrpc", "/xmlrpc.php", engine.Low),
		}}, "test")
	b := report.New(&engine.Result{Target: "https://b.test", Score: 100, Checks: 40, Requests: 50}, "test")
	return []report.Report{a, b}
}

// saveBatch writes reports as scan --json does for several targets.
func saveBatch(t *testing.T, name string, reports []report.Report, failed ...report.TargetError) string {
	t.Helper()
	var b bytes.Buffer
	if err := report.Write("json", &b, reports, report.WriteOptions{Many: true, Failed: failed}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCmdReportMatchesScanHTML(t *testing.T) {
	old, _ := diffFixtures(t)
	logo := filepath.Join(t.TempDir(), "logo.svg")
	if err := os.WriteFile(logo, []byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect width="4" height="4"/></svg>`), 0o600); err != nil {
		t.Fatal(err)
	}
	brand := []string{"--since", old, "--brand-name", "Acme Agency", "--brand-logo", logo}

	// scan --html, through the extension.
	scanned := filepath.Join(t.TempDir(), "scan.html")
	e, err := planned(t, append([]string{"--html", scanned}, brand...)...)
	if err != nil {
		t.Fatal(err)
	}
	var errs bytes.Buffer
	p := &scanPlan{targets: []string{"https://a.test", "https://b.test"}}
	if code, err := e.Finished(p, twoSites(), &errs); code != exitOK || err != nil {
		t.Fatalf("exit %d, %v", code, err)
	}
	if !strings.HasPrefix(errs.String(), "HTML report written to "+scanned+"\n") {
		t.Errorf("stderr:\n%s", errs.String())
	}

	// report --html on the JSON the same scan saved.
	saved := saveBatch(t, "scan.json", twoSites())
	rendered := filepath.Join(t.TempDir(), "report.html")
	errs.Reset()
	if code := cmdReport(append([]string{saved, "--html", "-o", rendered}, brand...), &bytes.Buffer{}, &errs); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	if errs.String() != "Report written to "+rendered+"\n" {
		t.Errorf("stderr: %q", errs.String())
	}
	got, want := readFile(t, rendered), readFile(t, scanned)
	if got != want {
		t.Errorf("report --html differs from scan --html:\n%s\n--- scan ---\n%s", got, want)
	}
	for _, s := range []string{"&lt;img src=x onerror=alert(1)&gt;", "Acme Agency security report: 2 sites", "compared with last-week.json", "Fixed since last-week.json (1)"} {
		if !strings.Contains(got, s) {
			t.Errorf("page lacks %q", s)
		}
	}
	if strings.Contains(got, "<script") || strings.Contains(got, "<img src=x") {
		t.Error("unsafe markup in the page")
	}
}

// report --sarif names a version: the saved report's, else this build's.
func TestCmdReportSARIFVersion(t *testing.T) {
	saved := saveBatch(t, "scan.json", twoSites())
	var out, errs bytes.Buffer
	if code := cmdReport([]string{saved, "--sarif"}, &out, &errs); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	reports, _, _ := readSaved(saved)
	want := `"version": "` + reports[0].Version + `"`
	if reports[0].Version == "" || !strings.Contains(out.String(), want) {
		t.Errorf("SARIF lacks %s:\n%.400s", want, out.String())
	}
	b, _ := os.ReadFile(saved)
	os.WriteFile(saved, bytes.ReplaceAll(b, []byte(`"version": "`+reports[0].Version+`"`), []byte(`"version": ""`)), 0o600)
	out.Reset()
	cmdReport([]string{saved, "--sarif"}, &out, &errs)
	if !strings.Contains(out.String(), `"version": "`+version+`"`) {
		t.Errorf("SARIF without a saved version lacks this build's:\n%.400s", out.String())
	}
}

func TestCmdReportFormats(t *testing.T) {
	saved := saveBatch(t, "scan.json", twoSites(), report.TargetError{Target: "https://down.test", Error: "connection refused"})
	reports, failed, err := readSaved(saved)
	if err != nil || len(reports) != 2 || len(failed) != 1 {
		t.Fatalf("%v %d %d", err, len(reports), len(failed))
	}
	// SARIF names the Tuner that wrote the saved report.
	o := report.WriteOptions{Many: true, Failed: failed, Version: reports[0].Version}
	for format, args := range map[string][]string{"md": {"--md"}, "sarif": {"--sarif"}, "json": {"--json"}, "html": {"--html"}} {
		var out, errs bytes.Buffer
		if code := cmdReport(append([]string{saved}, args...), &out, &errs); code != exitOK {
			t.Fatalf("%s: exit %d: %s", format, code, errs.String())
		}
		var want bytes.Buffer
		if err := report.Write(format, &want, reports, o); err != nil {
			t.Fatal(err)
		}
		if out.String() != want.String() {
			t.Errorf("%s output differs:\n%s\n--- want ---\n%s", format, out.String(), want.String())
		}
	}
	// JSON comes back as it was saved, failed targets included.
	var out bytes.Buffer
	cmdReport([]string{"--json", saved}, &out, &bytes.Buffer{})
	if out.String() != readFile(t, saved) {
		t.Errorf("json round trip:\n%s\n--- saved ---\n%s", out.String(), readFile(t, saved))
	}

	// -o picks the format from the extension; several files make one report.
	other := saveReport(t, "c.json", finding("xmlrpc", "/xmlrpc.php", engine.Low))
	md := filepath.Join(t.TempDir(), "all.md")
	if code := cmdReport([]string{saved, other, "-o", md}, &bytes.Buffer{}, &bytes.Buffer{}); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if got := readFile(t, md); strings.Count(got, "# Tuner report: ") != 3 || !strings.Contains(got, "# Not scanned") {
		t.Errorf("merged markdown:\n%s", got)
	}
}

func TestCmdReportErrors(t *testing.T) {
	saved := saveBatch(t, "scan.json", twoSites())
	big := filepath.Join(t.TempDir(), "big.png")
	if err := os.WriteFile(big, append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, report.MaxLogoSize)...), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{nil, exitUsage, "report takes one or more JSON reports"},
		{[]string{saved}, exitUsage, "pick a format: --html, --md, --sarif or --json"},
		{[]string{saved, "--md", "--html"}, exitUsage, "pick one of --html, --md, --sarif and --json"},
		{[]string{saved, "-o", "out.txt"}, exitUsage, "can't tell the format of out.txt"},
		{[]string{saved, "-o", "out.jsonl"}, exitUsage, "can't tell the format of out.jsonl"},
		{[]string{saved, "--html", "client.html"}, exitUsage, "client.html is not a JSON report; to write the report there, use -o client.html"},
		{[]string{saved, "--md", "--since", saved}, exitUsage, "--since marks what is new in the HTML report"},
		{[]string{saved, "--md", "--brand-name", "Acme"}, exitUsage, "--brand-name and --brand-logo only go on the HTML report (--html)"},
		{[]string{saved, "--html", "--brand-logo", big}, exitUsage, "is over 512 KB"},
		{[]string{saved, "--html", "--bogus"}, exitUsage, "flag provided but not defined"},
		{[]string{"/nonexistent/scan.json", "--html"}, exitError, "/nonexistent/scan.json"}, // the OS's wording differs on Windows
		{[]string{saved, "--html", "--since", "/nonexistent/old.json"}, exitError, "/nonexistent/old.json"},
		{[]string{saved, "--html", "-o", "/nonexistent/dir/out.html"}, exitError, "/nonexistent/dir/out.html"},
	} {
		var errs bytes.Buffer
		if code := cmdReport(c.args, &bytes.Buffer{}, &errs); code != c.code || !strings.Contains(errs.String(), c.want) {
			t.Errorf("%v: exit %d, want %d\n%s", c.args, code, c.code, errs.String())
		}
	}
	notJSON := filepath.Join(t.TempDir(), "notes.json")
	_ = os.WriteFile(notJSON, []byte(`{"hello": 1}`), 0o600)
	var errs bytes.Buffer
	if code := cmdReport([]string{notJSON, "--md"}, &bytes.Buffer{}, &errs); code != exitError || !strings.Contains(errs.String(), "not a Tuner JSON report") {
		t.Errorf("not a report: exit %d %s", code, errs.String())
	}
	var out bytes.Buffer
	if code := cmdReport([]string{"--help"}, &out, &bytes.Buffer{}); code != exitOK || !strings.HasPrefix(out.String(), "Usage:\n  rhythm tuner report") {
		t.Errorf("help: %d %s", code, out.String())
	}
}

func TestReportExtensionHTMLPlan(t *testing.T) {
	var ue usageError
	if _, err := planned(t, "--brand-name", "Acme"); !errors.As(err, &ue) || !strings.Contains(err.Error(), "only go on the HTML report") {
		t.Errorf("brand without --html: %v", err)
	}
	big := filepath.Join(t.TempDir(), "big.png")
	_ = os.WriteFile(big, make([]byte, report.MaxLogoSize+1), 0o600)
	if _, err := planned(t, "--html", "out.html", "--brand-logo", big); !errors.As(err, &ue) || !strings.Contains(err.Error(), "is over 512 KB") {
		t.Errorf("oversized logo: %v", err)
	}
	script := filepath.Join(t.TempDir(), "logo.svg")
	_ = os.WriteFile(script, []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`), 0o600)
	if _, err := planned(t, "--html", "out.html", "--brand-logo", script); !errors.As(err, &ue) || !strings.Contains(err.Error(), "<script> is not allowed") {
		t.Errorf("svg with a script: %v", err)
	}

	// --html alone needs no --since and -q keeps stderr quiet.
	out := filepath.Join(t.TempDir(), "one.html")
	e, err := planned(t, "--html", out)
	if err != nil {
		t.Fatal(err)
	}
	p := &scanPlan{targets: []string{"https://a.test"}}
	p.o.quiet = true
	var errs bytes.Buffer
	if code, err := e.Finished(p, twoSites()[:1], &errs); code != exitOK || err != nil || errs.Len() != 0 {
		t.Errorf("exit %d, %v, %q", code, err, errs.String())
	}
	if got := readFile(t, out); !strings.Contains(got, "<title>Security report: https://a.test</title>") {
		t.Errorf("page:\n%s", got)
	}
	e, _ = planned(t, "--html", "/nonexistent/dir/out.html")
	if code, err := e.Finished(p, twoSites(), &errs); code != exitError || err == nil {
		t.Errorf("unwritable: exit %d, %v", code, err)
	}
}
