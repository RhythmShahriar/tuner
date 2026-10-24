// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package diff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/report"
)

func rep(target string, fs ...engine.Finding) report.Report {
	for i := range fs {
		fs[i].Target = target
		if fs[i].Confidence == "" {
			fs[i].Confidence = "high"
		}
	}
	return report.New(&engine.Result{Target: target, Findings: fs}, "test")
}

func remote(id, path string, sev engine.Severity, advisories ...string) engine.Finding {
	f := engine.Finding{ID: id, Title: id, Severity: sev, URL: "https://a.test" + path, Path: path}
	for _, a := range advisories {
		f.Advisories = append(f.Advisories, engine.Advisory{ID: a, CVEs: []string{"CVE-" + a}})
	}
	return f
}

func local(root, id, path string) engine.Finding {
	return engine.Finding{ID: id, Title: id, Severity: engine.Medium, URL: "file://" + root + path, Path: path}
}

func ids(es []Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Finding.ID)
	}
	return out
}

func TestCompare(t *testing.T) {
	before := rep("https://a.test",
		remote("leak-dotenv", "/.env", engine.Critical),
		remote("xmlrpc", "/xmlrpc.php", engine.Low),
		remote("hdr-hsts-missing", "/", engine.Medium),
		remote("vuln-plugin-gallery", "/wp-content/plugins/gallery/", engine.Medium, "A1"),
		remote("vuln-plugin-forms", "/wp-content/plugins/forms/", engine.High, "B1", "B2"),
	)
	after := rep("https://a.test",
		remote("xmlrpc", "/xmlrpc.php", engine.Low),                                                // unchanged
		remote("hdr-hsts-missing", "/", engine.High),                                               // severity changed: new
		remote("vuln-plugin-gallery", "/wp-content/plugins/gallery/", engine.Critical, "A1", "A2"), // new advisory: new
		remote("vuln-plugin-forms", "/wp-content/plugins/forms/", engine.High, "B1"),               // one advisory fixed: unchanged
		remote("leak-git-config", "/.git/config", engine.High),                                     // new
	)
	res := Compare([]report.Report{before}, []report.Report{after})

	if got := strings.Join(ids(res.New), " "); got != "vuln-plugin-gallery hdr-hsts-missing leak-git-config" {
		t.Errorf("new = %s", got)
	}
	if got := strings.Join(ids(res.Fixed), " "); got != "leak-dotenv" {
		t.Errorf("fixed = %s", got)
	}
	if got := strings.Join(ids(res.Unchanged), " "); got != "vuln-plugin-forms xmlrpc" {
		t.Errorf("unchanged = %s", got)
	}
	for _, e := range res.New {
		switch e.Finding.ID {
		case "vuln-plugin-gallery":
			if len(e.NewAdvisories) != 1 || e.NewAdvisories[0].ID != "A2" {
				t.Errorf("gallery new advisories = %+v", e.NewAdvisories)
			}
			if got := e.Line(); got != "[CRITICAL] vuln-plugin-gallery (1 new: CVE-A2) (was medium) - https://a.test/wp-content/plugins/gallery/" {
				t.Errorf("line = %q", got)
			}
		case "hdr-hsts-missing":
			if e.Was != engine.Medium {
				t.Errorf("was = %q", e.Was)
			}
		}
	}
	if !res.NewAtOrAbove(engine.Critical) || !res.NewAtOrAbove(engine.High) {
		t.Error("NewAtOrAbove missed the new critical")
	}
	if got := res.Summary("last-week.json"); got != "3 new, 1 fixed since last-week.json" {
		t.Errorf("summary = %q", got)
	}
}

// A local copy that moved folder (another CI checkout) is the same site.
func TestCompareMovedLocalPath(t *testing.T) {
	before := rep("/tmp/a/wp", local("/tmp/a/wp", "local-wp-debug", "/wp-config.php"))
	after := rep("/home/runner/work/site", local("/home/runner/work/site", "local-wp-debug", "/wp-config.php"))
	res := Compare([]report.Report{before}, []report.Report{after})
	if len(res.New) != 0 || len(res.Fixed) != 0 || len(res.Unchanged) != 1 {
		t.Errorf("moved folder: %d new, %d fixed, %d unchanged", len(res.New), len(res.Fixed), len(res.Unchanged))
	}
}

// Staging compared with production: one report each, so hosts differ.
func TestCompareAcrossHosts(t *testing.T) {
	f := remote("leak-dotenv", "/.env", engine.Critical)
	g := f
	g.URL = "https://www.example.com/.env"
	res := Compare([]report.Report{rep("https://staging.example.com", f)}, []report.Report{rep("https://www.example.com", g)})
	if len(res.Unchanged) != 1 || len(res.New)+len(res.Fixed) != 0 {
		t.Errorf("staging vs production: %+v", res)
	}
}

func TestCompareBatch(t *testing.T) {
	dotenv := remote("leak-dotenv", "/.env", engine.Critical)
	before := []report.Report{rep("https://a.test", dotenv), rep("https://b.test", dotenv), rep("https://gone.test", dotenv)}
	after := []report.Report{rep("https://b.test/", dotenv), rep("http://a.test"), rep("https://c.test", dotenv)}
	res := Compare(before, after)
	if len(res.Fixed) != 1 || res.Fixed[0].Target != "https://a.test" {
		t.Errorf("fixed = %+v", res.Fixed)
	}
	if len(res.New) != 1 || res.New[0].Target != "https://c.test" {
		t.Errorf("new = %+v", res.New)
	}
	if len(res.Unchanged) != 1 || res.Unchanged[0].Target != "https://b.test/" {
		t.Errorf("unchanged = %+v", res.Unchanged)
	}
	// A target that wasn't scanned again is not "fixed".
	if len(res.NotScanned) != 1 || res.NotScanned[0] != "https://gone.test" {
		t.Errorf("not scanned = %v", res.NotScanned)
	}
}

func TestNewAtOrAbove(t *testing.T) {
	res := Compare([]report.Report{rep("https://a.test")}, []report.Report{rep("https://a.test", remote("xmlrpc", "/xmlrpc.php", engine.Low))})
	if res.NewAtOrAbove(engine.Medium) || !res.NewAtOrAbove(engine.Low) || !res.NewAtOrAbove(engine.Info) {
		t.Errorf("NewAtOrAbove wrong for one new low")
	}
}

func sample() Result {
	before := rep("https://a.test", remote("leak-dotenv", "/.env", engine.Critical), remote("xmlrpc", "/xmlrpc.php", engine.Low))
	after := rep("https://a.test", remote("xmlrpc", "/xmlrpc.php", engine.Low), remote("leak-git-config", "/.git/config", engine.High))
	return Compare([]report.Report{before}, []report.Report{after})
}

func TestWriteText(t *testing.T) {
	var b bytes.Buffer
	if err := WriteText(&b, sample(), "old.json"); err != nil {
		t.Fatal(err)
	}
	want := `1 new, 1 fixed, 1 unchanged since old.json

New:
[HIGH] leak-git-config - https://a.test/.git/config

Fixed:
[CRITICAL] leak-dotenv - https://a.test/.env
`
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

func TestWriteMarkdown(t *testing.T) {
	var b bytes.Buffer
	if err := WriteMarkdown(&b, sample(), "old_[1].json"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# Tuner changes since old\\_\\[1\\].json\n",
		"**1 new** · **1 fixed** · 1 unchanged\n",
		"## New\n\n| Severity | Finding | Path | Target |\n|---|---|---|---|\n| HIGH | leak-git-config | `/.git/config` | https://a.test |\n",
		"## Fixed\n",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in:\n%s", want, b.String())
		}
	}
}

func TestWriteJSON(t *testing.T) {
	var b bytes.Buffer
	if err := WriteJSON(&b, sample(), "old.json"); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Schema string         `json:"schema"`
		Since  string         `json:"since"`
		Counts map[string]int `json:"counts"`
		New    []Entry        `json:"new"`
		Fixed  []Entry        `json:"fixed"`
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != Schema || got.Since != "old.json" || got.Counts["new"] != 1 || got.Counts["fixed"] != 1 ||
		got.Counts["unchanged"] != 1 || got.New[0].Finding.ID != "leak-git-config" || !strings.HasPrefix(got.New[0].Fingerprint, "v1:") {
		t.Errorf("got %s", b.String())
	}
}

// review: a scan that stopped early must not list what it never reached
// as fixed.
func TestCompareIncompleteScan(t *testing.T) {
	before := rep("https://a.test",
		remote("leak-dotenv", "/.env", engine.Critical),
		remote("xmlrpc", "/xmlrpc.php", engine.Low),
	)
	after := rep("https://a.test", remote("xmlrpc", "/xmlrpc.php", engine.Low))
	after.SetStatus(report.Status{StoppedBy: "waf", BlockedBy: "cloudflare"})
	res := Compare([]report.Report{before}, []report.Report{after})
	if len(res.Fixed) != 0 || len(res.NotSeen) != 1 || res.NotSeen[0].Finding.ID != "leak-dotenv" {
		t.Errorf("fixed %v, not seen %v", ids(res.Fixed), ids(res.NotSeen))
	}
	if got := res.Summary("old.json"); got != "0 new, 0 fixed since old.json; 1 not seen (scan incomplete)" {
		t.Errorf("summary %q", got)
	}
	var b bytes.Buffer
	_ = WriteText(&b, res, "old.json")
	want := `0 new, 0 fixed, 1 unchanged since old.json; 1 not seen (scan incomplete)
Incomplete: blocked by Cloudflare challenge

Not seen, scan incomplete:
[CRITICAL] leak-dotenv - https://a.test/.env
`
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
	b.Reset()
	_ = WriteMarkdown(&b, res, "old.json")
	for _, want := range []string{"· 1 not seen (scan incomplete)\n", "> ⚠️ Incomplete: blocked by Cloudflare challenge\n", "## Not seen, scan incomplete\n"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in:\n%s", want, b.String())
		}
	}

	// Without vulnerability data only the advisory findings are unknown.
	before = rep("https://a.test",
		remote("leak-dotenv", "/.env", engine.Critical),
		remote("vuln-plugin-gallery", "/wp-content/plugins/gallery/", engine.High, "A1"),
	)
	after = rep("https://a.test")
	after.SetStatus(report.Status{Complete: true, VulnData: "missing"})
	res = Compare([]report.Report{before}, []report.Report{after})
	if got, want := strings.Join(ids(res.Fixed), ","), "leak-dotenv"; got != want {
		t.Errorf("fixed %s, want %s", got, want)
	}
	if got := ids(res.NotSeen); len(got) != 1 || got[0] != "vuln-plugin-gallery" {
		t.Errorf("not seen %v", got)
	}
	if len(res.Incomplete) != 1 || !strings.Contains(res.Incomplete[0], "vulnerability data missing") {
		t.Errorf("incomplete %q", res.Incomplete)
	}
}
