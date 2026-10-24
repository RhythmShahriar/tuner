// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

func sampleResult(target string) *engine.Result {
	return &engine.Result{
		Target:      target,
		Fingerprint: fingerprint.Result{Tech: []string{"wordpress", "php"}, WordPress: "6.4", PHP: "8.1", Server: "nginx"},
		Score:       85,
		Checks:      30,
		Requests:    42,
		Duration:    1500 * time.Millisecond,
		Findings: []engine.Finding{{
			ID: "env-file", Title: ".env file exposed", Severity: engine.Critical, Confidence: "high",
			Target: target, URL: target + "/.env", Path: "/.env",
			Evidence: engine.Evidence{Request: "GET /.env", Status: 200, Matched: []string{"DB_PASSWORD=su****ue"}},
			Fix:      "Block dotfiles <Files .*>",
		}},
	}
}

// oldJSON is how report.JSON encoded reports before the writer registry.
func oldJSON(reports []Report, many bool) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if len(reports) == 1 && !many {
		_ = enc.Encode(reports[0])
	} else {
		if reports == nil {
			reports = []Report{}
		}
		_ = enc.Encode(reports)
	}
	return b.String()
}

func TestWriteJSONMatchesJSON(t *testing.T) {
	one := []Report{New(sampleResult("https://a.test"), "0.4.0")}
	two := append(one, New(sampleResult("https://b.test"), "0.4.0"))
	for _, tc := range []struct {
		name    string
		reports []Report
		many    bool
	}{
		{"one", one, false},
		{"one of a batch", one, true},
		{"two", two, true},
		{"none", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var viaWrite, viaJSON bytes.Buffer
			if err := Write("json", &viaWrite, tc.reports, WriteOptions{Many: tc.many}); err != nil {
				t.Fatal(err)
			}
			if err := JSON(&viaJSON, tc.reports, tc.many); err != nil {
				t.Fatal(err)
			}
			if viaWrite.String() != viaJSON.String() {
				t.Errorf("Write and JSON differ:\n%s\n---\n%s", viaWrite.String(), viaJSON.String())
			}
			if want := oldJSON(tc.reports, tc.many); viaWrite.String() != want {
				t.Errorf("JSON changed shape:\n%s\n---\n%s", viaWrite.String(), want)
			}
		})
	}
}

func TestWriteJSONArrayAndFailed(t *testing.T) {
	one := []Report{New(sampleResult("https://a.test"), "0.4.0")}
	var b bytes.Buffer
	if err := Write("json", &b, one, WriteOptions{Array: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.String(), "[") {
		t.Errorf("--json-array with one target is not an array:\n%s", b.String())
	}

	b.Reset()
	failed := []TargetError{{Target: "https://down.test", Error: "can't reach down.test"}}
	if err := Write("json", &b, one, WriteOptions{Failed: failed}); err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("not an array: %v\n%s", err, b.String())
	}
	if len(got) != 2 || got[1]["target"] != "https://down.test" || got[1]["error"] != "can't reach down.test" {
		t.Errorf("failed target missing: %v", got)
	}
	if got[0]["baselined"] != float64(0) {
		t.Errorf("baselined should always be present, got %v", got[0]["baselined"])
	}
}

func TestWriteSARIFAndMarkdownMatchWrappers(t *testing.T) {
	reports := []Report{New(sampleResult("https://a.test"), "0.4.0")}
	var a, b bytes.Buffer
	_ = Write("sarif", &a, reports, WriteOptions{Version: "0.4.0"})
	_ = SARIF(&b, reports, "0.4.0")
	if a.String() != b.String() || !strings.Contains(a.String(), `"version": "0.4.0"`) {
		t.Errorf("sarif differs or lacks the version:\n%s", a.String())
	}
	a.Reset()
	b.Reset()
	_ = Write("md", &a, reports, WriteOptions{})
	_ = Markdown(&b, reports)
	if a.String() != b.String() || !strings.Contains(a.String(), "# Tuner report: https://a.test") {
		t.Errorf("markdown differs:\n%s", a.String())
	}
}

func TestMarkdownListsFailedTargets(t *testing.T) {
	var b bytes.Buffer
	_ = Write("md", &b, nil, WriteOptions{Failed: []TargetError{{Target: "down.test", Error: "timeout | retry"}}})
	if !strings.Contains(b.String(), "# Not scanned") || !strings.Contains(b.String(), `| down.test | timeout \| retry |`) {
		t.Errorf("failed target missing:\n%s", b.String())
	}
}

func TestWriteUnknownFormat(t *testing.T) {
	err := Write("pdf", &bytes.Buffer{}, nil, WriteOptions{})
	if err == nil || !strings.Contains(err.Error(), `unknown report format "pdf"`) || !strings.Contains(err.Error(), "json") {
		t.Errorf("err = %v", err)
	}
}

func TestRegisterWriter(t *testing.T) {
	RegisterWriter("test-txt", ".TXT", func(w io.Writer, r []Report, _ WriteOptions) error {
		_, err := fmt.Fprintf(w, "reports: %d", len(r))
		return err
	})
	defer func() {
		writersMu.Lock()
		delete(writers, "test-txt")
		writersMu.Unlock()
	}()
	var b bytes.Buffer
	if err := Write("test-txt", &b, []Report{{}}, WriteOptions{}); err != nil || b.String() != "reports: 1" {
		t.Errorf("got %q, %v", b.String(), err)
	}
	if got := FormatForExt("out/report.TXT"); got != "test-txt" {
		t.Errorf("FormatForExt(.TXT) = %q", got)
	}
}

func TestFormatForExt(t *testing.T) {
	for path, want := range map[string]string{
		"report.json":      "json",
		"r.jsonl":          "jsonl",
		"r.ndjson":         "jsonl",
		"tuner.sarif":      "sarif",
		"REPORT.MD":        "md",
		"notes.markdown":   "md",
		"report.txt":       "",
		"report":           "",
		"dir.json/report":  "",
		"./a/b/c.d/r.json": "json",
	} {
		if got := FormatForExt(path); got != want {
			t.Errorf("FormatForExt(%q) = %q, want %q", path, got, want)
		}
	}
}

// The jsonl writer has nothing to add: findings were streamed already.
func TestWriteJSONLIsEmpty(t *testing.T) {
	var b bytes.Buffer
	if err := Write("jsonl", &b, []Report{New(sampleResult("https://a.test"), "1")}, WriteOptions{}); err != nil || b.Len() != 0 {
		t.Errorf("jsonl wrote %q, %v", b.String(), err)
	}
}
