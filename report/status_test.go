// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/RhythmShahriar/tuner/engine"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./report -update to create it)", err)
	}
	if got != string(want) {
		t.Errorf("%s differs (go test ./report -update rewrites it):\n%s\n--- want ---\n%s", name, got, want)
	}
}

var partial = Status{Complete: false, StoppedBy: "interrupted", VulnData: "missing"}

func partialResult() *engine.Result {
	return &engine.Result{
		Target: "https://a.test", Score: 98, Checks: 32, Requests: 14, Errors: 1,
		Findings: []engine.Finding{{ID: "xmlrpc", Title: "XML-RPC enabled", Severity: engine.Low, Confidence: "high", URL: "https://a.test/xmlrpc.php", Path: "/xmlrpc.php"}},
	}
}

func TestSummaryShowsIncomplete(t *testing.T) {
	old := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(old)

	for _, plain := range []bool{true, false} {
		var b bytes.Buffer
		p := NewPretty(&b, &b, PrettyOptions{Plain: plain})
		p.SetStatus(partial)
		p.Summary(partialResult(), "https://a.test", 0)
		name := map[bool]string{true: "summary-partial-plain.golden", false: "summary-partial-tty.golden"}[plain]
		golden(t, name, b.String())

		out := sgr.ReplaceAllString(b.String(), "")
		inc := strings.Index(out, "Incomplete: interrupted")
		vuln := strings.Index(out, "Score excludes known vulnerabilities (vulnerability data missing)")
		score := strings.Index(out, "Score 98/100")
		if !plain {
			score = strings.Index(out, "TUNE SCORE")
		}
		if inc < 0 || vuln < 0 || score < 0 || inc > score || vuln > score {
			t.Errorf("plain=%v: the incomplete notes must come before the score:\n%s", plain, out)
		}
		if !strings.Contains(out, "1 error") || strings.Contains(out, "1 errors") {
			t.Errorf("plain=%v: want \"1 error\":\n%s", plain, out)
		}
	}
}

// A whole scan prints no notes. That stays the default.
func TestSummaryCompleteHasNoNotes(t *testing.T) {
	var b bytes.Buffer
	p := NewPretty(&b, &b, PrettyOptions{Plain: true})
	res := partialResult()
	res.Errors = 3
	p.Summary(res, "https://a.test", 0)
	if strings.Contains(b.String(), "Incomplete") || strings.Contains(b.String(), "excludes") || !strings.Contains(b.String(), "3 errors") {
		t.Errorf("got:\n%s", b.String())
	}
}

func TestPlural(t *testing.T) {
	for _, tc := range []struct {
		n    int64
		want string
	}{{0, "0 errors"}, {1, "1 error"}, {2, "2 errors"}} {
		if got := plural(tc.n, "error"); got != tc.want {
			t.Errorf("plural(%d) = %q", tc.n, got)
		}
	}
}

func TestStatusNotes(t *testing.T) {
	for _, tc := range []struct {
		s    Status
		want []string
	}{
		{Status{Complete: true, VulnData: "ok"}, nil},
		{Status{Complete: true, VulnData: "off"}, nil},
		{Status{StoppedBy: "interrupted"}, []string{"Incomplete: interrupted"}},
		{Status{StoppedBy: "max-time"}, []string{"Incomplete: stopped by --max-time"}},
		{Status{StoppedBy: "waf", BlockedBy: "cloudflare"}, []string{"Incomplete: blocked by Cloudflare challenge"}},
		{Status{StoppedBy: "waf"}, []string{"Incomplete: blocked by a firewall challenge"}},
		{Status{Complete: true, BlockedBy: "sucuri"}, []string{"Incomplete: blocked by Sucuri challenge"}},
		{Status{StoppedBy: "home-status"}, []string{"Incomplete: the home page did not load"}},
		{Status{StoppedBy: "budget"}, []string{"Incomplete: stopped at the request budget"}},
		{Status{}, []string{"Incomplete: the scan did not finish"}},
		{Status{StoppedBy: "odd\x1b"}, []string{"Incomplete: stopped by odd�"}},
		{Status{Complete: true, VulnData: "partial"}, []string{"Score may miss known vulnerabilities (vulnerability data partial)"}},
		{Status{StoppedBy: "max-time", VulnData: "missing"}, []string{"Incomplete: stopped by --max-time", "Score excludes known vulnerabilities (vulnerability data missing)"}},
	} {
		got := tc.s.Notes()
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%+v: %q, want %q", tc.s, got, tc.want)
		}
	}
}

func TestEveryFormatShowsIncomplete(t *testing.T) {
	r := New(partialResult(), "0.4.0")
	if !r.Complete {
		t.Fatal("New must start complete")
	}
	r.SetStatus(partial)
	reports := []Report{r}

	var b bytes.Buffer
	_ = Write("json", &b, reports, WriteOptions{})
	var j map[string]any
	if err := json.Unmarshal(b.Bytes(), &j); err != nil {
		t.Fatal(err)
	}
	if j["complete"] != false || j["stopped_by"] != "interrupted" || j["vuln_data"] != "missing" {
		t.Errorf("json: complete=%v stopped_by=%v vuln_data=%v", j["complete"], j["stopped_by"], j["vuln_data"])
	}
	if _, ok := j["blocked_by"]; ok {
		t.Error("json: empty blocked_by should be left out")
	}

	b.Reset()
	_ = Write("sarif", &b, reports, WriteOptions{})
	var s struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful        bool
				ToolExecutionNotifications []struct {
					Level   string
					Message struct{ Text string }
				}
			}
		}
	}
	if err := json.Unmarshal(b.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	inv := s.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful || len(inv.ToolExecutionNotifications) != 2 || inv.ToolExecutionNotifications[0].Message.Text != "Incomplete: interrupted" ||
		inv.ToolExecutionNotifications[0].Level != "warning" {
		t.Errorf("sarif invocation: %+v", inv)
	}

	b.Reset()
	_ = Write("md", &b, reports, WriteOptions{})
	md := b.String()
	want := "# Tuner report: https://a.test\n\n> ⚠️ **Incomplete:** interrupted\n>\n> ⚠️ Score excludes known vulnerabilities \\(vulnerability data missing\\)\n\n**Tune score 98/100**"
	if !strings.HasPrefix(md, want) {
		t.Errorf("markdown:\n%s", md)
	}

	// A whole scan: complete in JSON, a successful SARIF run, no quote.
	whole := []Report{New(partialResult(), "0.4.0")}
	b.Reset()
	_ = Write("sarif", &b, whole, WriteOptions{})
	s.Runs = nil // omitted notifications would keep the old ones
	_ = json.Unmarshal(b.Bytes(), &s)
	if !s.Runs[0].Invocations[0].ExecutionSuccessful || len(s.Runs[0].Invocations[0].ToolExecutionNotifications) != 0 {
		t.Errorf("sarif for a whole scan: %+v", s.Runs[0].Invocations)
	}
	b.Reset()
	_ = Write("md", &b, whole, WriteOptions{})
	if strings.Contains(b.String(), "Incomplete") {
		t.Errorf("markdown for a whole scan:\n%s", b.String())
	}
	b.Reset()
	_ = Write("json", &b, whole, WriteOptions{})
	if !strings.Contains(b.String(), `"complete": true`) {
		t.Errorf("json for a whole scan:\n%s", b.String())
	}
}
