// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package fixgen

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/checks"
	"github.com/RhythmShahriar/tuner/engine"
)

var update = flag.Bool("update", false, "rewrite the golden bundles")

func builtIn(t *testing.T) []*engine.Check {
	t.Helper()
	all, err := engine.LoadChecks(checks.FS)
	if err != nil {
		t.Fatal(err)
	}
	return all
}

func load(t *testing.T, name string) []Finding {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := ParseReport(data)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

// golden compares got with testdata/name; go test -update rewrites it.
// The goldens are also what ci-release feeds to nginx -t and apachectl -t.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s differs (go test ./fixgen -update to accept):\n%s", name, got)
	}
}

func TestGoldenBundles(t *testing.T) {
	findings := load(t, "batch.json")
	for _, server := range Servers {
		b, err := Build(findings, server, builtIn(t))
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := b.Write(&out, "0.4.0"); err != nil {
			t.Fatal(err)
		}
		golden(t, server+".conf", out.String())
	}
}

func TestDedupe(t *testing.T) {
	b, err := Build(load(t, "batch.json"), "nginx", nil)
	if err != nil {
		t.Fatal(err)
	}
	var dot, logs *Block
	for i, blk := range b.Blocks {
		switch blk.Checks[0] {
		case "leak-dotenv":
			dot = &b.Blocks[i]
		case "laravel-log":
			logs = &b.Blocks[i]
		}
	}
	if dot == nil || strings.Join(dot.Checks, " ") != "leak-dotenv leak-ds-store" || len(dot.URLs) != 3 {
		t.Errorf("dotfile block = %+v", dot)
	}
	if logs == nil || strings.Join(logs.Checks, " ") != "laravel-log wp-debug-log" {
		t.Errorf("log block = %+v", logs)
	}
	for _, blk := range b.Blocks {
		if blk.Checks[0] == "hdr-hsts-missing" && len(blk.URLs) != 2 {
			t.Errorf("hsts block should list both sites once: %+v", blk)
		}
	}

	// The same report twice is the same bundle.
	twice, err := Build(append(load(t, "batch.json"), load(t, "batch.json")...), "nginx", nil)
	if err != nil {
		t.Fatal(err)
	}
	if twice.Findings != b.Findings || len(twice.Blocks) != len(b.Blocks) {
		t.Errorf("twice: %d findings in %d blocks, want %d in %d", twice.Findings, len(twice.Blocks), b.Findings, len(b.Blocks))
	}
}

// Reports from before fix_server carry no fixes; the built-in check with
// the finding's ID supplies them.
func TestOldReportFallsBackToChecks(t *testing.T) {
	findings := load(t, "old.json")
	b, err := Build(findings, "apache", builtIn(t))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := b.Write(&out, "dev"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# leak-git\n#   https://shop.example.test/.git/HEAD\nRedirectMatch 404 /\\.git\n",
		"# wp-dir-listing\n#   https://shop.example.test/wp-content/uploads/\nOptions -Indexes\n",
		"# No apache snippet for: php-display-errors\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}

	// Without checks to fall back on, nothing is known.
	b, _ = Build(findings, "apache", nil)
	if len(b.Blocks) != 0 || len(b.Without) != 3 {
		t.Errorf("no fallback: %+v", b)
	}
}

func TestPlan(t *testing.T) {
	// Without Tuner's checks every snippet comes from the report, and
	// the plan says so for each block.
	b, err := Build(load(t, "batch.json"), "apache", nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := b.WritePlan(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"apache bundle: 5 snippets for 9 findings\n",
		"  leak-dotenv, leak-ds-store (3 URLs) (from the report)\n",
		"no apache snippet: hdr-server-version, vuln-plugin-akismet, wp-user-enum-rest\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}

	// With them, only snippets no check has are marked.
	b, err = Build(load(t, "batch.json"), "apache", builtIn(t))
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := b.WritePlan(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "  leak-dotenv, leak-ds-store (3 URLs)\n") {
		t.Errorf("a check's snippet is marked as from the report:\n%s", out.String())
	}
}

func TestCommentsAreInert(t *testing.T) {
	b, err := Build([]Finding{{
		ID: "leak-x", URL: "https://a.test/x\nlocation / { return 200; }\r\x1b[2J",
		Fixes: map[string]string{"nginx": "location = /x {\n\tdeny all;\x1b]0;x\x07\n}"},
	}}, "nginx", nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := b.Write(&out, "dev"); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, "return 200") && !strings.HasPrefix(line, "#") {
			t.Errorf("URL text escaped its comment: %q", line)
		}
	}
	if strings.ContainsAny(out.String(), "\r\x1b\x07") || !strings.Contains(out.String(), "location = /x {\n\tdeny all;]0;x\n}\n") {
		t.Errorf("control bytes in bundle: %q", out.String())
	}
}

// Dry runs print report IDs to the terminal, so they lose control bytes too.
func TestPlanIsInert(t *testing.T) {
	b, err := Build([]Finding{
		{ID: "leak-x\x1b[2J", URL: "https://a.test/x", Fixes: map[string]string{"nginx": "location = /x { deny all; }"}},
		{ID: "leak-y\x1b]0;owned\x07", URL: "https://a.test/y"},
	}, "nginx", nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := b.WritePlan(&out); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out.String(), "\x1b\x07") || !strings.Contains(out.String(), "  leak-x[2J (1 URL) (from the report)\n") {
		t.Errorf("control bytes in plan: %q", out.String())
	}
}

func TestManyURLsAreSummedUp(t *testing.T) {
	var fs []Finding
	for _, host := range strings.Split("a b c d e f g h i j k l", " ") {
		fs = append(fs, Finding{ID: "wp-xmlrpc", URL: "https://" + host + ".test/xmlrpc.php", Fixes: map[string]string{"nginx": "location = /xmlrpc.php { deny all; }"}})
	}
	b, _ := Build(fs, "nginx", nil)
	var out bytes.Buffer
	_ = b.Write(&out, "dev")
	if !strings.Contains(out.String(), "#   https://j.test/xmlrpc.php\n#   and 2 more\n") || strings.Contains(out.String(), "k.test") {
		t.Errorf("not summed up:\n%s", out.String())
	}
}

func TestParseReportErrors(t *testing.T) {
	for in, want := range map[string]string{
		"":                             "not a JSON report",
		"<html>":                       "not a JSON report",
		`{"findings": []}`:             "not a Tuner JSON report",
		`[{"schema": "other/v1"}]`:     "not a Tuner JSON report",
		`{"schema": "rhythm-tuner/v0"`: "unexpected end",
	} {
		_, err := ParseReport([]byte(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseReport(%q) = %v, want %q", in, err, want)
		}
	}
	if fs, err := ParseReport([]byte(`{"schema": "rhythm-tuner/v0", "findings": []}`)); err != nil || len(fs) != 0 {
		t.Errorf("empty report: %v %v", fs, err)
	}
}

func TestUnknownServer(t *testing.T) {
	if _, err := Build(nil, "caddy", nil); err == nil || !strings.Contains(err.Error(), `unknown server "caddy"`) {
		t.Errorf("err = %v", err)
	}
}

// A report's snippet for a known check is ignored, so an edited report
// can't slip its own directives into a bundle under Tuner's name. Other
// IDs keep the report's snippet with a warning.
func TestReportSnippetsDontOverrideChecks(t *testing.T) {
	b, err := Build([]Finding{
		{ID: "leak-dotenv", URL: "https://a.test/.env", Fixes: map[string]string{"nginx": "location / { proxy_pass http://attacker.test; }"}},
		{ID: "acme-old-admin", URL: "https://a.test/old-admin/", Fixes: map[string]string{"nginx": "location /old-admin/ { deny all; }"}},
	}, "nginx", builtIn(t))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := b.Write(&out, "dev"); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Contains(got, "proxy_pass") || !strings.Contains(got, "# leak-dotenv\n#   https://a.test/.env\nlocation ~ /\\.(?!well-known) { deny all; }\n") {
		t.Errorf("built-in snippet not used:\n%s", got)
	}
	want := "# acme-old-admin\n#   https://a.test/old-admin/\n# Taken from the report: no Tuner check has this ID. Review it with care.\nlocation /old-admin/ { deny all; }\n"
	if !strings.Contains(got, want) {
		t.Errorf("missing %q in:\n%s", want, got)
	}
	if strings.Count(got, "Taken from the report") != 1 {
		t.Errorf("the warning belongs to the report's own snippet only:\n%s", got)
	}
}
