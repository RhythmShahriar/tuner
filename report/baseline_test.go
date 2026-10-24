// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
)

func TestFingerprint(t *testing.T) {
	f := engine.Finding{ID: "env-file", URL: "https://www.example.test/.env", Path: "/.env", Target: "https://www.example.test"}
	fp := Fingerprint(f, "")
	if !strings.HasPrefix(fp, "v1:") || len(fp) != 3+32 {
		t.Fatalf("fingerprint %q is not v1: plus 32 hex digits", fp)
	}
	// Pinned: changing the scheme silently would bring back every
	// baselined finding for every user.
	if fp != "v1:89333af193f211d97cde1f54fa097d7b" {
		t.Errorf("v1 fingerprint changed: %s", fp)
	}

	same := []engine.Finding{
		{ID: "env-file", URL: "https://staging.example.test/.env"},                      // another host
		{ID: "env-file", URL: "http://admin:pw@www.example.test:8443/.env?cache=1#top"}, // scheme, user info, port, query
		{ID: "env-file", URL: "https://www.example.test/.env", Title: "changed", Severity: engine.Low},
	}
	for _, g := range same {
		if got := Fingerprint(g, ""); got != fp {
			t.Errorf("%s: fingerprint %s, want %s", g.URL, got, fp)
		}
	}
	differ := []engine.Finding{
		{ID: "env-file", URL: "https://www.example.test/.env.local"},
		{ID: "env-backup", URL: "https://www.example.test/.env"},
		{ID: "env-file", URL: "https://www.example.test/blog/.env"},
	}
	for _, g := range differ {
		if Fingerprint(g, "") == fp {
			t.Errorf("%s %s shares the fingerprint", g.ID, g.URL)
		}
	}
}

func TestFingerprintLocal(t *testing.T) {
	a := engine.Finding{ID: "local-wp-debug", URL: "file:///tmp/a/wp/wp-config.php", Path: "/wp-config.php", Target: "/tmp/a/wp"}
	b := engine.Finding{ID: "local-wp-debug", URL: "file:///tmp/b/moved/wp-config.php", Path: "/wp-config.php", Target: "/tmp/b/moved"}
	if Fingerprint(a, "") != Fingerprint(b, "") {
		t.Error("a moved folder changed the fingerprint")
	}
	if Fingerprint(a, "/tmp/a/wp") != Fingerprint(b, "/tmp/b/moved/") {
		t.Error("an explicit root changed the fingerprint")
	}
	win := engine.Finding{ID: "local-wp-debug", URL: "file:///C:/sites/wp/wp-config.php", Target: `C:\sites\wp`}
	if Fingerprint(win, "") != Fingerprint(a, "") {
		t.Error("a Windows root is not stripped")
	}
	// Outside the root (or no usable root) the finding's own path decides.
	odd := engine.Finding{ID: "local-wp-debug", URL: "file:///elsewhere/wp-config.php", Path: "wp-config.php", Target: "/tmp/a/wp"}
	if Fingerprint(odd, "") != Fingerprint(a, "") {
		t.Error("the path fallback differs")
	}
	rootFile := engine.Finding{ID: "x", URL: "file:///tmp/a/wp", Target: "/tmp/a/wp"}
	if location(rootFile, "") != "/" {
		t.Errorf("root location = %q", location(rootFile, ""))
	}
}

func writeBaseline(t *testing.T, results ...*engine.Result) string {
	t.Helper()
	var reports []Report
	for _, r := range results {
		reports = append(reports, New(r, "test"))
	}
	var b bytes.Buffer
	if err := JSON(&b, reports, len(reports) > 1); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func gallery(advisories ...engine.Advisory) engine.Finding {
	var ev []string
	for _, a := range advisories {
		ev = append(ev, advisoryLine(a))
	}
	title := "gallery 1.5: 1 known vulnerability"
	if len(advisories) > 1 {
		title = "gallery 1.5: " + string(rune('0'+len(advisories))) + " known vulnerabilities"
	}
	worst := engine.Info
	for _, a := range advisories {
		if a.Severity.Rank() < worst.Rank() {
			worst = a.Severity
		}
	}
	return engine.Finding{
		ID: "vuln-plugin-gallery", Title: title, Severity: worst, Confidence: "high",
		Target: "/tmp/a/wp", URL: "file:///tmp/a/wp/wp-content/plugins/gallery/readme.txt", Path: "/wp-content/plugins/gallery/readme.txt",
		Evidence: engine.Evidence{Request: "version match", Matched: ev}, Advisories: advisories,
		Impact: "2 published vulnerabilities affect gallery 1.5.", Tags: []string{"vuln", "plugin", "wordpress", "known-exploited"},
	}
}

var (
	lowXSS   = engine.Advisory{ID: "wf-1", Title: "Stored XSS", CVEs: []string{"CVE-2026-0001"}, Severity: engine.Low, FixedIn: "1.6"}
	critSQLi = engine.Advisory{ID: "wf-2", Title: "SQL injection", CVEs: []string{"CVE-2026-0002"}, Severity: engine.Critical, KEV: true, FixedIn: "1.7"}
)

// qa #3: a new critical KEV advisory on a baselined plugin must come back.
func TestBaselineKeepsNewAdvisories(t *testing.T) {
	base, err := LoadBaseline(writeBaseline(t, &engine.Result{Target: "/tmp/a/wp", Findings: []engine.Finding{gallery(lowXSS)}}))
	if err != nil {
		t.Fatal(err)
	}
	now := gallery(lowXSS, critSQLi)
	if base.Has(now) {
		t.Fatal("Has hides a finding with a new advisory")
	}
	res := &engine.Result{Target: "/tmp/a/wp", Findings: []engine.Finding{now}, Score: 70}
	if n := base.Filter(res); n != 0 {
		t.Errorf("hid %d findings", n)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings: %+v", res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != engine.Critical || len(f.Advisories) != 1 || f.Advisories[0].ID != "wf-2" {
		t.Errorf("want only the critical advisory, got %s %+v", f.Severity, f.Advisories)
	}
	if f.Title != "gallery 1.5: 1 new known vulnerability" {
		t.Errorf("title %q", f.Title)
	}
	if len(f.Evidence.Matched) != 1 || !strings.Contains(f.Evidence.Matched[0], "SQL injection") || !strings.Contains(f.Evidence.Matched[0], "[actively exploited]") {
		t.Errorf("evidence %q", f.Evidence.Matched)
	}
	if !slices.Contains(f.Tags, "known-exploited") || !strings.Contains(f.Impact, "The baseline accepts 1 of them") {
		t.Errorf("tags %v, impact %q", f.Tags, f.Impact)
	}
	if res.Score != engine.Score(res.Findings) || res.Score == 100 {
		t.Errorf("score %d not recomputed", res.Score)
	}
	if now.Title != "gallery 1.5: 2 known vulnerabilities" || len(now.Advisories) != 2 {
		t.Error("Filter changed the scanned finding in place")
	}

	// With both advisories accepted, the finding is hidden.
	base, _ = LoadBaseline(writeBaseline(t, &engine.Result{Target: "/tmp/a/wp", Findings: []engine.Finding{gallery(critSQLi, lowXSS)}}))
	res = &engine.Result{Findings: []engine.Finding{gallery(lowXSS, critSQLi)}}
	if n := base.Filter(res); n != 1 || len(res.Findings) != 0 || res.Score != 100 {
		t.Errorf("hid %d, left %+v, score %d", n, res.Findings, res.Score)
	}
}

// A low advisory that is new next to an accepted critical one must not
// keep the finding critical. The KEV tag goes with the critical one.
func TestBaselineNarrowsSeverityDown(t *testing.T) {
	base, _ := LoadBaseline(writeBaseline(t, &engine.Result{Target: "/tmp/a/wp", Findings: []engine.Finding{gallery(critSQLi)}}))
	res := &engine.Result{Findings: []engine.Finding{gallery(critSQLi, lowXSS)}}
	base.Filter(res)
	f := res.Findings[0]
	if f.Severity != engine.Low || slices.Contains(f.Tags, "known-exploited") {
		t.Errorf("severity %s, tags %v", f.Severity, f.Tags)
	}
}

// users P2: a baseline from /tmp/a/wp hides the same findings under
// /tmp/b/moved. One from staging hides them on www.
func TestBaselineIsPortable(t *testing.T) {
	local := func(root string) *engine.Result {
		res := &engine.Result{Target: root}
		for _, p := range []string{"/wp-config.php", "/.env", "/wp-content/debug.log"} {
			res.Findings = append(res.Findings, engine.Finding{
				ID: "local" + strings.ReplaceAll(p, "/", "-"), Severity: engine.High, Target: root, URL: "file://" + root + p, Path: p,
			})
		}
		g := gallery(lowXSS, critSQLi)
		g.Target, g.URL = root, "file://"+root+g.Path
		res.Findings = append(res.Findings, g)
		return res
	}
	base, err := LoadBaseline(writeBaseline(t, local("/tmp/a/wp")))
	if err != nil {
		t.Fatal(err)
	}
	moved := local("/tmp/b/moved")
	if n := base.Filter(moved); n != 4 || len(moved.Findings) != 0 {
		t.Errorf("moved folder: hid %d, left %+v", n, moved.Findings)
	}

	remote := func(host string) *engine.Result {
		return &engine.Result{Target: "https://" + host, Findings: []engine.Finding{
			{ID: "env-file", Severity: engine.Critical, Target: "https://" + host, URL: "https://" + host + "/.env", Path: "/.env"},
			{ID: "xmlrpc", Severity: engine.Low, Target: "https://" + host, URL: "https://" + host + "/xmlrpc.php", Path: "/xmlrpc.php"},
		}}
	}
	base, _ = LoadBaseline(writeBaseline(t, remote("staging.example.test")))
	www := remote("www.example.test")
	if n := base.Filter(www); n != 2 {
		t.Errorf("www: hid %d, left %+v", n, www.Findings)
	}
	// A different place is still new.
	www = remote("www.example.test")
	www.Findings[0].URL = "https://www.example.test/shop/.env"
	if n := base.Filter(www); n != 1 || www.Findings[0].ID != "env-file" {
		t.Errorf("hid %d, left %+v", n, www.Findings)
	}
}

// review: a batch baseline that accepts a finding on one client's site
// must not hide the same finding on another site, in the batch or not.
func TestBaselineBatchIsPerSite(t *testing.T) {
	site := func(host string, advisories ...engine.Advisory) *engine.Result {
		g := gallery(advisories...)
		g.Target, g.URL = "https://"+host, "https://"+host+g.Path
		return &engine.Result{Target: "https://" + host, Findings: []engine.Finding{
			g, {ID: "xmlrpc", Severity: engine.Low, Target: "https://" + host, URL: "https://" + host + "/xmlrpc.php", Path: "/xmlrpc.php"},
		}}
	}
	path := writeBaseline(t, site("client-a.test", critSQLi), &engine.Result{Target: "https://client-c.test", Findings: []engine.Finding{}})
	base, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	b := site("client-b.test", critSQLi)
	if n := base.Filter(b); n != 0 || len(b.Findings) != 2 || b.Score == 100 {
		t.Errorf("client-b: hid %d, left %d, score %d", n, len(b.Findings), b.Score)
	}
	if base.Has(b.Findings[0]) {
		t.Error("Has accepts client-a's finding on client-b")
	}
	// The same site, written another way, still matches.
	a := site("client-a.test", critSQLi)
	a.Target = "http://Client-A.test/"
	if n := base.Filter(a); n != 2 || len(a.Findings) != 0 {
		t.Errorf("client-a: hid %d, left %+v", n, a.Findings)
	}
	// A new advisory on the accepted plugin still comes back narrowed.
	a = site("client-a.test", critSQLi, lowXSS)
	if base.Filter(a); len(a.Findings) != 1 || len(a.Findings[0].Advisories) != 1 || a.Findings[0].Advisories[0].ID != "wf-1" {
		t.Errorf("client-a with a new advisory: %+v", a.Findings)
	}

	// A batch saved while only client-a was reachable is still a batch
	// baseline: it must not hide client-a's finding on client-b.
	partial := filepath.Join(t.TempDir(), "partial.json")
	var buf bytes.Buffer
	if err := Write("json", &buf, []Report{New(site("client-a.test", critSQLi), "test")}, WriteOptions{Many: true, Failed: []TargetError{{Target: "https://client-b.test", Error: "timeout"}}}); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(partial, buf.Bytes(), 0o600)
	base, _ = LoadBaseline(partial)
	if b := site("client-b.test", critSQLi); base.Filter(b) != 0 {
		t.Errorf("batch with a failed target hid client-a's finding on client-b: left %+v", b.Findings)
	}
	if a := site("client-a.test", critSQLi); base.Filter(a) != 2 {
		t.Errorf("batch with a failed target: client-a left %+v", a.Findings)
	}

	// A one-element array is a single-site baseline, so it still matches
	// across hosts.
	one := filepath.Join(t.TempDir(), "one.json")
	buf.Reset()
	if err := Write("json", &buf, []Report{New(site("staging.test", critSQLi), "test")}, WriteOptions{Many: true}); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(one, buf.Bytes(), 0o600)
	base, _ = LoadBaseline(one)
	if b := site("www.test", critSQLi); base.Filter(b) != 2 {
		t.Errorf("single-site array: left %+v", b.Findings)
	}
}

// Order of findings and advisories in either file doesn't matter.
func TestBaselineOrderIndependent(t *testing.T) {
	a := &engine.Result{Findings: []engine.Finding{gallery(lowXSS, critSQLi), {ID: "env-file", URL: "https://a.test/.env"}}}
	b := &engine.Result{Findings: []engine.Finding{{ID: "env-file", URL: "https://a.test/.env"}, gallery(critSQLi, lowXSS)}}
	ba, _ := LoadBaseline(writeBaseline(t, a))
	bb, _ := LoadBaseline(writeBaseline(t, b))
	for i, base := range []Baseline{ba, bb} {
		for j, res := range []*engine.Result{
			{Findings: slices.Clone(a.Findings)},
			{Findings: slices.Clone(b.Findings)},
		} {
			if n := base.Filter(res); n != 2 {
				t.Errorf("baseline %d, scan %d: hid %d", i, j, n)
			}
		}
	}
}

// Reports saved before fingerprints still work, with a note to re-save.
func TestBaselineOldFormat(t *testing.T) {
	old := `[{"schema":"rhythm-tuner/v0","target":"https://a.test","findings":[
		{"id":"env-file","target":"https://a.test","url":"https://a.test/.env","path":"/.env","severity":"critical"},
		{"id":"vuln-plugin-gallery","target":"https://a.test","url":"https://a.test/wp-content/plugins/gallery/readme.txt",
		 "path":"/wp-content/plugins/gallery/readme.txt","advisories":[{"id":"wf-1","title":"Stored XSS"}]}]}]`
	path := filepath.Join(t.TempDir(), "old.json")
	_ = os.WriteFile(path, []byte(old), 0o600)
	base, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	g := gallery(lowXSS, critSQLi)
	g.Target, g.URL = "https://a.test", "https://a.test"+g.Path
	res := &engine.Result{Findings: []engine.Finding{
		{ID: "env-file", Target: "https://a.test", URL: "https://a.test/.env", Path: "/.env", Severity: engine.Critical}, g,
	}}
	if n := base.Filter(res); n != 1 || len(res.Findings) != 1 || len(res.Findings[0].Advisories) != 1 || res.Findings[0].Advisories[0].ID != "wf-2" {
		t.Errorf("hid %d, left %+v", n, res.Findings)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "predates finding fingerprints; save a fresh one by running the scan without --baseline and with --json -o "+path) {
		t.Errorf("warnings %q", res.Warnings)
	}
	// The legacy ID+URL key covers a finding whose fingerprint would differ.
	if !base.Has(engine.Finding{ID: "env-file", URL: "https://a.test/.env", Path: "/other"}) {
		t.Error("legacy key ignored")
	}

	// A fresh report carries fingerprints, so no note.
	base, _ = LoadBaseline(writeBaseline(t, &engine.Result{Findings: []engine.Finding{{ID: "env-file", URL: "https://a.test/.env"}}}))
	res = &engine.Result{Findings: []engine.Finding{{ID: "env-file", URL: "https://b.test/.env"}}}
	if n := base.Filter(res); n != 1 || len(res.Warnings) != 0 {
		t.Errorf("hid %d, warnings %q", n, res.Warnings)
	}
}

func TestBaselineErrorsAndZero(t *testing.T) {
	var zero Baseline
	res := &engine.Result{Findings: []engine.Finding{{ID: "x"}}, Score: 90}
	if zero.Has(res.Findings[0]) || zero.Filter(res) != 0 || res.Score != 90 {
		t.Error("a zero Baseline filtered something")
	}
	path := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(path, []byte("not json"), 0o600)
	if _, err := LoadBaseline(path); err == nil || !strings.Contains(err.Error(), "not a Tuner JSON report") {
		t.Errorf("err = %v", err)
	}
	if _, err := LoadBaseline(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file loaded")
	}
	// JSON that isn't a Tuner report would hide nothing without a word.
	for name, doc := range map[string]string{
		"sarif":  `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[]}`,
		"object": `{}`,
		"array":  `[]`,
		"other":  `[{"schema":"other/v1","findings":[]}]`,
	} {
		_ = os.WriteFile(path, []byte(doc), 0o600)
		if _, err := LoadBaseline(path); err == nil || !strings.HasPrefix(err.Error(), "not a Tuner JSON report") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// Narrowing keeps the advisors' evidence lines and their "…and N more".
func TestNarrowEvidence(t *testing.T) {
	var advs []engine.Advisory
	for i := range 8 {
		advs = append(advs, engine.Advisory{ID: string(rune('a' + i)), Title: "flaw " + string(rune('a'+i)), Severity: engine.High})
	}
	f := gallery(advs...)
	f.Title = "gallery 1.5: 8 known vulnerabilities"
	f.Evidence.Matched = append(f.Evidence.Matched[:5:5], "…and 3 more")
	f.Evidence.Matched[1] = "HIGH flaw b (as the advisor wrote it)"
	got := narrow(f, advs[1:]) // a is accepted; 7 are new
	want := []string{"HIGH flaw b (as the advisor wrote it)", f.Evidence.Matched[2], f.Evidence.Matched[3], f.Evidence.Matched[4], "HIGH flaw f", "…and 2 more"}
	if !slices.Equal(got.Evidence.Matched, want) {
		t.Errorf("evidence\n%q\nwant\n%q", got.Evidence.Matched, want)
	}
	if got.Title != "gallery 1.5: 7 new known vulnerabilities" {
		t.Errorf("title %q", got.Title)
	}
	odd := f
	odd.Title = "Some other wording"
	if got := narrow(odd, advs[1:2]); got.Title != "Some other wording (1 new)" {
		t.Errorf("title %q", got.Title)
	}
}
