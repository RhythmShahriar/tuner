// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/matchers"
)

func TestSafeText(t *testing.T) {
	for in, want := range map[string]string{
		"plain text":            "plain text",
		"tab\there":             "tab\there",
		"bell\a":                "bell�",
		"\x1b]52;c;aGk=\x07":    "�]52;c;aGk=�",
		"erase\x1b[2K":          "erase�[2K",
		"line\nbreak\r":         "line�break�",
		"del\x7f":               "del�",
		"csi\u009b31m":          "csi�31m",
		"raw\x9bbyte":           "raw�byte",
		"café ✖ 🔴":              "café ✖ 🔴",
		"nul\x00":               "nul�",
		"next line \u0085 here": "next line � here",
	} {
		if got := SafeText(in); got != want {
			t.Errorf("SafeText(%q) = %q, want %q", in, got, want)
		}
	}
	if got := safeBlock("a\r\nb\nc\x1b"); got != "a\nb\nc�" {
		t.Errorf("safeBlock = %q", got)
	}
}

func TestMDText(t *testing.T) {
	for in, want := range map[string]string{
		"WordPress 6.4":                "WordPress 6.4",
		"<img src=https://x/p.gif>":    `\<img src=https://x/p.gif\>`,
		"[click](javascript:alert(1))": `\[click\]\(javascript:alert\(1\)\)`,
		"a|b":                          `a\|b`,
		"# heading":                    `\# heading`,
		"*bold* _it_ `code` ~s~ !x \\": `\*bold\* \_it\_ \` + "`code\\`" + ` \~s\~ \!x \\`,
		"two\nlines\r\nhere":           "two lines here",
		"&lt;img src=x&gt;":            "&amp;lt;img src=x&amp;gt;",
		"esc\x1b[31mred":               `esc` + "�" + `\[31mred`,
		"@org/team and @alice":         "@\u2060org/team and @\u2060alice",
	} {
		if got := MDText(in); got != want {
			t.Errorf("MDText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMDCode(t *testing.T) {
	for in, want := range map[string]string{
		"/wp-config.php":  "`/wp-config.php`",
		"a`b":             "``a`b``",
		"a``b`":           "``` a``b` ```",
		"`":               "`` ` ``",
		"":                "` `",
		"x|y":             "`x|y`",
		"one\ntwo":        "`one two`",
		"\x1b]0;t\x07<i>": "`�]0;t�<i>`",
	} {
		if got := MDCode(in); got != want {
			t.Errorf("MDCode(%q) = %q, want %q", in, got, want)
		}
	}
	if got := MDCodeCell("x|y"); got != "`x\\|y`" {
		t.Errorf("MDCodeCell = %q", got)
	}
	if got := mdFence("a\n```\nb"); got != "````\na\n```\nb\n````" {
		t.Errorf("mdFence = %q", got)
	}
}

func TestSafeLink(t *testing.T) {
	for _, tc := range []struct{ text, href, want string }{
		{"CVE-2024-1", "https://wpscan.com/vulnerability/1", "[CVE-2024-1](https://wpscan.com/vulnerability/1)"},
		{"x", "http://a.test/p?q=1", "[x](http://a.test/p?q=1)"},
		{"click", "javascript:alert(1)", "click"},
		{"click", "JaVaScRiPt:alert(1)", "click"},
		{"data", "data:text/html;base64,PHNjcmlwdD4=", "data"},
		{"rel", "/relative/path", "rel"},
		{"ftp", "ftp://a.test/f", "ftp"},
		{"paren", "https://a.test/a)(b", "[paren](https://a.test/a%29%28b)"},
		{"user", "https://admin:pw@a.test/", "[user](https://a.test/)"},
		{"t", "https://ref.test/?q=|evil|cell|", "[t](https://ref.test/?q=%7Cevil%7Ccell%7C)"}, // a table cell stays one cell
		{"[evil](javascript:x)", "https://a.test/", `[\[evil\]\(javascript:x\)](https://a.test/)`},
	} {
		if got := SafeLink(tc.text, tc.href); got != tc.want {
			t.Errorf("SafeLink(%q, %q) = %q, want %q", tc.text, tc.href, got, tc.want)
		}
	}
}

func TestSanitizedDeepCopies(t *testing.T) {
	in := engine.Result{
		Target:   "a\x1bb",
		Findings: []engine.Finding{{Title: "t\x07", Fix: "line1\nline2\x1b", Evidence: engine.Evidence{Matched: []string{"m\x1b"}}}},
		TLS:      &matchers.TLSInfo{Version: "TLS\x1b", NotAfter: time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)},
	}
	out := sanitized(in)
	if out.Target != "a�b" || out.Findings[0].Title != "t�" || out.Findings[0].Evidence.Matched[0] != "m�" {
		t.Errorf("not cleaned: %+v", out)
	}
	if out.Findings[0].Fix != "line1\nline2�" {
		t.Errorf("Fix lost its line break: %q", out.Findings[0].Fix)
	}
	if out.TLS.Version != "TLS�" || !out.TLS.NotAfter.Equal(in.TLS.NotAfter) {
		t.Errorf("TLS: %+v", out.TLS)
	}
	if in.Target != "a\x1bb" || in.Findings[0].Evidence.Matched[0] != "m\x1b" || in.TLS.Version != "TLS\x1b" {
		t.Error("sanitized changed its input")
	}
}

// evil is a string a hostile site or file name could hold: an OSC 52
// clipboard write, a line erase, a bell, a C1 CSI, a raw 0x9b byte, an
// HTML image and a javascript: link.
const evil = "x\x1b]52;c;cm0gLXJmIH4=\x07\x1b[2K\x1b[1A\u009b31m\x9b<img src=https://attacker.invalid/px.gif>[click](javascript:alert(1))"

func evilResult() *engine.Result {
	f := engine.Finding{
		ID: "env-file" + evil, Title: ".env exposed " + evil, Severity: engine.Critical, Confidence: "low",
		Caveat: "likely: " + evil, Target: "https://a.test", URL: "https://a.test/.env" + evil, Path: "/.env" + evil,
		Evidence: engine.Evidence{Request: "GET /.env" + evil, Status: 200, Matched: []string{"APP_NAME=" + evil},
			Secrets: []matchers.Secret{{Kind: "password", Name: "DB" + evil, Masked: "su****" + evil}}},
		Impact: "impact " + evil, Fix: "fix " + evil + "\nsecond line", References: []string{"javascript:alert(1)", "https://a.test/" + evil},
		Tags: []string{"tag" + evil}, Source: "source" + evil,
	}
	vuln := engine.Finding{
		ID: "vuln-plugin-evil", Title: "evil" + evil + " 1.0: 1 known vulnerability", Severity: engine.High, Confidence: "high",
		Target: "https://a.test", URL: "https://a.test/wp-content/plugins/evil/readme.txt", Path: "/wp-content/plugins/evil/readme.txt",
		Evidence:   engine.Evidence{Request: "version match", Matched: []string{"HIGH " + evil}},
		Advisories: []engine.Advisory{{ID: "a1" + evil, Title: "XSS " + evil, CVEs: []string{"CVE-1" + evil}, Severity: engine.High, FixedIn: "2" + evil, References: []string{"javascript:alert(1)"}}},
		Source:     "Wordfence" + evil,
	}
	low := f
	low.Severity, low.ID = engine.Low, "low"+evil
	return &engine.Result{
		Target: "https://a.test" + evil,
		Fingerprint: fingerprint.Result{Tech: []string{"wordpress", "php"}, WordPress: "6.4" + evil, PHP: "8.1" + evil, Server: "nginx " + evil,
			Components: []fingerprint.Component{{Type: "plugin", Slug: "evil" + evil, Version: "1.0" + evil, Source: "readme" + evil}}},
		Checks: 3, Requests: 5, Score: 50,
		Findings: []engine.Finding{f, vuln, low},
		Warnings: []string{"warning " + evil},
	}
}

// sgr matches the color sequences lipgloss writes; any other escape in
// TTY output came from the site.
var sgr = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func assertInert(t *testing.T, name, out string, allowSGR bool) {
	t.Helper()
	if allowSGR {
		out = sgr.ReplaceAllString(out, "")
	}
	if !utf8.ValidString(out) {
		t.Errorf("%s: output is not valid UTF-8 (a raw 0x9b byte got through)", name)
	}
	for _, r := range out {
		if r == 0x1b || r == 0x07 || r == 0x9b || (r < 0x20 && r != '\n' && r != '\t') || (r >= 0x7f && r < 0xa0) {
			t.Errorf("%s: control character %U in output:\n%q", name, r, out)
			return
		}
	}
	if strings.Contains(out, `\u001b`) || strings.Contains(out, `\u0007`) {
		t.Errorf("%s: an escaped control character reached the output", name)
	}
}

// codeSpans strips inline code and fenced blocks, where markup is inert.
var codeSpans = regexp.MustCompile("(?s)(`{3,})\n.*?\n`{3,}|(`+)[^`].*?`+")

func assertSafeMarkdown(t *testing.T, md string) {
	t.Helper()
	rest := codeSpans.ReplaceAllString(md, "")
	if i := strings.Index(rest, "<img"); i >= 0 && (i == 0 || rest[i-1] != '\\') {
		t.Errorf("raw <img outside code in markdown:\n%s", rest)
	}
	if strings.Contains(strings.ToLower(rest), "](javascript:") {
		t.Errorf("javascript: link in markdown:\n%s", md)
	}
	for _, l := range strings.Split(rest, "\n") {
		if strings.Contains(l, "](") && !regexp.MustCompile(`\]\(https?://`).MatchString(l) && !strings.Contains(l, `\]\(`) {
			t.Errorf("a link that is not http(s): %q", l)
		}
	}
}

func TestEveryFormatIsInert(t *testing.T) {
	old := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(old)

	for _, plain := range []bool{true, false} {
		res := evilResult()
		var out, errs bytes.Buffer
		p := NewPretty(&out, &errs, PrettyOptions{Plain: plain})
		p.Header("0.4.0"+evil, res.Target)
		p.Fingerprint(res.Fingerprint)
		for _, f := range res.Findings {
			p.Finding(f)
		}
		p.Request(engine.RequestLog{Method: "GET", URL: "https://a.test/" + evil, Status: 200, Err: errors.New("read " + evil)})
		p.Summary(res, res.Target, Hidden{})
		name := map[bool]string{true: "plain", false: "tty"}[plain]
		if !strings.Contains(out.String(), "nginx") || !strings.Contains(errs.String(), "ERR read") {
			t.Fatalf("%s: rendering lost content:\n%s\n%s", name, out.String(), errs.String())
		}
		assertInert(t, name, out.String(), !plain)
		assertInert(t, name+" stderr", errs.String(), !plain)
		if res.Findings[0].Title != ".env exposed "+evil {
			t.Error("Pretty changed the caller's result")
		}
	}

	res := evilResult()
	reports := []Report{New(res, "0.4.0"+evil)}
	if res.Target != "https://a.test"+evil {
		t.Error("New changed the caller's result")
	}
	for _, format := range []string{"json", "sarif", "md"} {
		var b bytes.Buffer
		if err := Write(format, &b, reports, WriteOptions{Version: "0.4.0" + evil, Failed: []TargetError{{Target: evil, Error: evil}}}); err != nil {
			t.Fatal(err)
		}
		assertInert(t, format, b.String(), false)
		if format == "md" {
			assertSafeMarkdown(t, b.String())
		}
	}
}
