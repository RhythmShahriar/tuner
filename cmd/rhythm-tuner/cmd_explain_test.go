// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
)

// explain runs the explain command on the built-in checks, offline.
func explain(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("TUNER_CHECKS_URL", "http://127.0.0.1:1") // never reach the real release
	var out, errb bytes.Buffer
	code = cmdExplain(append(args, "--no-check-updates"), &out, &errb)
	return code, out.String(), errb.String()
}

func TestExplainCheck(t *testing.T) {
	code, out, errOut := explain(t, "leak-dotenv")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"leak-dotenv: .env file exposed",
		"Severity:   critical",
		"Requests:   /.env /.env.local",
		"\nImpact\n  Anyone can read database passwords",
		"\nFix\n  Deny access to dotfiles",
		"\nReferences\n  https://owasp.org/",
		"\nMore\n  " + findingReference + "#leak-dotenv\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestExplainServerSnippets(t *testing.T) {
	c := &engine.Check{ID: "leak-x", Name: "X", Severity: engine.High,
		FixServer: engine.FixServer{Nginx: "location = /x { deny all; }\n", Apache: "<Files x>\n  Require all denied\n</Files>"}}
	e, ok := lookupExplanation("leak-x", []*engine.Check{c}, nil)
	if !ok {
		t.Fatal("not found")
	}
	var b strings.Builder
	e.write(&b)
	for _, want := range []string{"\nnginx\n  location = /x { deny all; }\n", "\nApache\n  <Files x>\n    Require all denied\n  </Files>\n"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in:\n%s", want, b.String())
		}
	}
}

func TestExplainJSON(t *testing.T) {
	code, out, _ := explain(t, "--json", "hdr-hsts-missing")
	var e explanation
	if err := json.Unmarshal([]byte(out), &e); code != exitOK || err != nil {
		t.Fatalf("exit %d, %v:\n%s", code, err, out)
	}
	if e.ID != "hdr-hsts-missing" || e.Kind != "check" || e.Severity != engine.Medium || e.Reference != findingReference+"#hdr-hsts-missing" {
		t.Errorf("%+v", e)
	}
}

func TestExplainSuggests(t *testing.T) {
	code, out, errOut := explain(t, "leak-dotnev")
	if code != exitUsage || out != "" {
		t.Errorf("exit %d, stdout %q", code, out)
	}
	if want := `rhythm tuner: no check or rule "leak-dotnev"; did you mean leak-dotenv?`; !strings.Contains(errOut, want) {
		t.Errorf("stderr %q, want %q", errOut, want)
	}

	code, _, errOut = explain(t, "zzzz")
	if code != exitUsage || !strings.Contains(errOut, `no check or rule "zzzz"; list them with: rhythm tuner checks`) {
		t.Errorf("exit %d: %s", code, errOut)
	}
}

func TestExplainUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := cmdExplain(nil, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "explain takes one finding ID") {
		t.Errorf("no id: exit %d, %q", code, errb.String())
	}
	out.Reset()
	if code := cmdExplain([]string{"--help"}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "rhythm tuner explain <id>") {
		t.Errorf("help: exit %d, %q", code, out.String())
	}
}

// Advisor findings come from Go code; explain finds them in the rule
// registry. The fake rule stands in until vulns registers its own.
func TestExplainRule(t *testing.T) {
	engine.RegisterRules("explain-test",
		engine.Rule{ID: "zz-fake-", Prefix: true, Title: "Fake advisory", Severity: engine.High, Tags: []string{"fake"}},
		engine.Rule{ID: "zz-fake-plugin-", Prefix: true, Title: "Fake plugin advisory", HelpURI: "https://example.test/help"},
		engine.Rule{ID: "yy-exact-rule", Title: "Fake exact rule", Severity: engine.Low},
	)
	code, out, errOut := explain(t, "zz-fake-akismet")
	if code != exitOK || !strings.Contains(out, "zz-fake-akismet: Fake advisory") ||
		!strings.Contains(out, findingReference+"#zz-fake\n") || !strings.Contains(out, "not a YAML check") {
		t.Errorf("prefix rule: exit %d %s\n%s", code, errOut, out)
	}
	if _, out, _ := explain(t, "zz-fake-plugin-akismet"); !strings.Contains(out, "Fake plugin advisory") || !strings.Contains(out, "https://example.test/help") {
		t.Errorf("longest prefix should win:\n%s", out)
	}
	if _, out, _ := explain(t, "yy-exact-rule"); !strings.Contains(out, "Fake exact rule") {
		t.Errorf("exact rule:\n%s", out)
	}
	if _, _, errOut := explain(t, "yy-exatc-rule"); !strings.Contains(errOut, "did you mean yy-exact-rule?") {
		t.Errorf("suggestion from rules: %s", errOut)
	}
}

func TestSuggestIDs(t *testing.T) {
	known := []string{"leak-dotenv", "leak-git", "leak-svn", "wp-xmlrpc", "hdr-hsts-missing"}
	for in, want := range map[string]string{
		"leak-dotnev": "leak-dotenv",
		"leak-gti":    "leak-git",
		"hdr-hsts":    "hdr-hsts-missing",
		"xmlrpc":      "",
	} {
		if got := strings.Join(suggestIDs(in, known), " "); got != want {
			t.Errorf("suggestIDs(%q) = %q, want %q", in, got, want)
		}
	}
}
