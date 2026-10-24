// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package checktest

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/RhythmShahriar/tuner/checks"
	"github.com/RhythmShahriar/tuner/engine"
)

// goodCheck passes every lint rule; each case below breaks one.
const goodCheck = `id: leak-thing
name: Thing exposed
severity: high
request:
  path: ["/thing.txt", "/{{host}}.thing?v=1.2"]
match:
  all:
    - status: 200
    - words: ["THING"]
fix_server:
  nginx: |
    # deny it
    location = /thing.txt { deny all; }
  apache: |
    <Files "thing.txt">
      Require all denied
    </Files>
references:
  - https://example.test/thing
`

const goodFixture = `positive:
  - name: exposed
    routes:
      /thing.txt: {body: THING}
negative:
  - name: missing
    routes: {}
`

func lintOne(check, fixture string) []Issue {
	fsys := fstest.MapFS{"leaks/thing.yaml": {Data: []byte(check)}}
	if fixture != "" {
		fsys["leaks/thing_test.yaml"] = &fstest.MapFile{Data: []byte(fixture)}
	}
	return Lint(fsys)
}

func TestLintGoodCheck(t *testing.T) {
	if issues := lintOne(goodCheck, goodFixture); len(issues) != 0 {
		t.Errorf("issues: %v", issues)
	}
	if res := Run(fstest.MapFS{"leaks/thing.yaml": {Data: []byte(goodCheck)}, "leaks/thing_test.yaml": {Data: []byte(goodFixture)}}); res[0].Failed(true) {
		t.Errorf("fixtures: %+v", res)
	}
}

func TestLintRules(t *testing.T) {
	r := func(old, new string) string {
		if !strings.Contains(goodCheck, old) {
			panic(old)
		}
		return strings.Replace(goodCheck, old, new, 1)
	}
	for _, tc := range []struct {
		name, check, fixture, rule, want string
	}{
		{"camel id", r("leak-thing", "leakThing"), goodFixture, "id", "lower-case words joined by hyphens"},
		{"one word id", r("leak-thing", "thing"), goodFixture, "id", "lower-case words joined by hyphens"},
		{"unknown prefix", r("leak-thing", "acme-thing"), goodFixture, "id", "start it with one of hdr-, laravel-, leak-"},
		{"advisor prefix", r("leak-thing", "wp-core-thing"), goodFixture, "id", "belongs to vulnerability matching"},
		// The engine refuses these at load time, so lint reports the load error.
		{"post", r("request:\n", "request:\n  method: POST\n"), goodFixture, "load", "checks may only use GET or HEAD"},
		{"traversal", r("/thing.txt\", \"/{{host}}", "/../etc/passwd\", \"/{{host}}"), goodFixture, "query", "path traversal"},
		{"encoded dot", r("/thing.txt\"", "/%2e%2e/thing.txt\""), goodFixture, "query", `"%2e" in the path looks like a payload`},
		{"sql in query", r("?v=1.2", "?id=1'+OR+'1'='1"), goodFixture, "load", "the query may only hold plain name=value pairs"},
		{"script in query", r("?v=1.2", "?q=<script>"), goodFixture, "load", "the query may only hold plain name=value pairs"},
		{"other template", r("{{host}}.thing", "{{path}}.thing"), goodFixture, "query", "only {{host}} may be templated"},
		{"no guard", r(`    - words: ["THING"]`, "    - header: {Content-Type: text/plain}"), goodFixture, "baseline", "needs not_baseline: true or a regex"},
		{"any without guard", r("    - words: [\"THING\"]\n", "  any:\n    - words: [\"THING\"]\n    - status: 206\n"), goodFixture, "baseline", "needs not_baseline"},
		{"no https reference", r("https://example.test/thing", "http://example.test/thing"), goodFixture, "reference", "needs at least one https:// reference"},
		{"no fixture", goodCheck, "", "fixtures", "missing: every check needs positive and negative cases"},
		{"no negative", goodCheck, "positive: [{name: a}]\n", "fixtures", "has 1 and 0"},
		{"bad fixture", goodCheck, "positive: [{name: a, bogus: 1}]\n", "fixtures", "field bogus not found"},
		{"nginx no semicolon", r("{ deny all; }", "{ deny all }"), goodFixture, "fix-server", "fix_server.nginx: line 2: directive before } has no ;"},
		{"nginx unbalanced", r("{ deny all; }", "{ deny all;"), goodFixture, "fix-server", "1 unclosed {"},
		{"nginx extra brace", r("{ deny all; }", "{ deny all; } }"), goodFixture, "fix-server", "} without {"},
		{"apache unclosed", r("    </Files>\n", ""), goodFixture, "fix-server", `fix_server.apache: <files> is never closed`},
		{"apache crossed", r("    </Files>\n", "    </FilesMatch>\n"), goodFixture, "fix-server", "</FilesMatch> does not close an open section"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issues := lintOne(tc.check, tc.fixture)
			var found bool
			for _, i := range issues {
				if i.Rule != tc.rule {
					t.Errorf("unexpected %s issue: %s", i.Rule, i)
					continue
				}
				found = found || strings.Contains(i.Message, tc.want)
			}
			if !found {
				t.Errorf("want a %s issue with %q, got %v", tc.rule, tc.want, issues)
			}
		})
	}
}

// LintCheck keeps its own method and payload rules for checks built in
// code, which never pass through the engine's loader.
func TestLintCheckMethodAndPayload(t *testing.T) {
	c := &engine.Check{ID: "leak-thing", File: "leaks/thing.yaml", Request: engine.Request{
		Method: "POST", Path: []string{"/thing.txt?id=1'+OR+'1'='1", "/q?x=<script>"},
	}, References: []string{"https://example.test/thing"}}
	var got []string
	for _, i := range LintCheck(fstest.MapFS{}, c) {
		got = append(got, i.Rule+": "+i.Message)
	}
	all := strings.Join(got, "\n")
	for _, want := range []string{"method: request.method POST: checks only read", "query: request.path \"/thing.txt?id=1'+OR+'1'='1\"", "looks like a payload"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
}

func TestLintGuards(t *testing.T) {
	for _, guard := range []string{"not_baseline: true", `regex: "x"`, "magic: \"00\""} {
		check := strings.Replace(goodCheck, `words: ["THING"]`, guard, 1)
		if issues := lintOne(check, goodFixture); len(issues) != 0 {
			t.Errorf("%s: %v", guard, issues)
		}
	}
	// A check on / alone needs no guard: the home page is never a soft-404.
	home := strings.NewReplacer(`["/thing.txt", "/{{host}}.thing?v=1.2"]`, `["/"]`, `words: ["THING"]`, "missing_header: [X-Thing]").Replace(goodCheck)
	if issues := lintOne(home, goodFixture); len(issues) != 0 {
		t.Errorf("home page check: %v", issues)
	}
}

func TestNginxSyntax(t *testing.T) {
	for snippet, want := range map[string]string{
		"":                                 "",
		"server_tokens off;":               "",
		`add_header X "a;b}" always;`:      "",
		"location ~ /\\.git { deny all; }": "",
		"# only a comment { \n":            "",
		"autoindex off":                    "last directive has no ;",
		";":                                "line 1: empty directive",
		`add_header X "open;`:              "unclosed quote",
	} {
		if got := nginxSyntax(snippet); got != want {
			t.Errorf("nginxSyntax(%q) = %q, want %q", snippet, got, want)
		}
	}
}

func TestApacheSyntax(t *testing.T) {
	for snippet, want := range map[string]string{
		"Options -Indexes": "",
		`<FilesMatch "^\."> Require all denied </FilesMatch>`:              "",
		"<IfModule mod_headers.c>\n<Files \"x>y\">\n</Files>\n</IfModule>": "",
		"# <Files x>":     "",
		"</Files>":        "line 1: </Files> does not close an open section",
		"<If \"true\">\n": "<if> is never closed",
	} {
		if got := apacheSyntax(snippet); got != want {
			t.Errorf("apacheSyntax(%q) = %q, want %q", snippet, got, want)
		}
	}
}

func TestQuickBudget(t *testing.T) {
	fsys := fstest.MapFS{}
	for i := range QuickBudget + 1 {
		id := fmt.Sprintf("leak-thing%d", i)
		fsys["leaks/"+id+".yaml"] = &fstest.MapFile{Data: []byte(strings.NewReplacer(
			"id: leak-thing", "id: "+id+"\nprofile: quick",
			`["/thing.txt", "/{{host}}.thing?v=1.2"]`, fmt.Sprintf(`["/thing%d.txt"]`, i),
		).Replace(goodCheck))}
		fsys["leaks/"+id+"_test.yaml"] = &fstest.MapFile{Data: []byte(goodFixture)}
	}
	issues := Lint(fsys)
	if len(issues) != 1 || issues[0].Rule != "budget" || !strings.Contains(issues[0].Message, "requests 31 distinct paths, more than 30") {
		t.Errorf("issues: %v", issues)
	}
	delete(fsys, "leaks/leak-thing0.yaml")
	delete(fsys, "leaks/leak-thing0_test.yaml")
	if issues := Lint(fsys); len(issues) != 0 {
		t.Errorf("at the budget: %v", issues)
	}
}

func TestLintLoadError(t *testing.T) {
	issues := Lint(fstest.MapFS{"leaks/x.yaml": {Data: []byte("id: x")}})
	if len(issues) != 1 || issues[0].Rule != "load" || issues[0].String() != "checks: load: leaks/x.yaml: missing name" {
		t.Errorf("issues: %v", issues)
	}
}

// Every built-in check passes lint.
func TestBuiltInChecksPassLint(t *testing.T) {
	for _, i := range Lint(checks.FS) {
		t.Error(i)
	}
}

// A scaffolded check passes lint and its fixtures as it is.
func TestScaffoldPasses(t *testing.T) {
	for _, id := range []string{"leak-thing", "wp-old-backup", "srv-status"} {
		check, fixture, err := Scaffold(id)
		if err != nil {
			t.Fatal(err)
		}
		fsys := fstest.MapFS{"new/" + id + ".yaml": {Data: check}, "new/" + id + "_test.yaml": {Data: fixture}}
		if issues := Lint(fsys); len(issues) != 0 {
			t.Errorf("%s: lint: %v", id, issues)
		}
		for _, r := range Run(fsys) {
			if r.Failed(true) {
				t.Errorf("%s: %s: %v %v", id, r, r.Problems, r.Leaks)
			}
		}
	}
	if _, _, err := Scaffold("Bad_ID"); err == nil || !strings.Contains(err.Error(), "lower-case words") {
		t.Errorf("bad id: %v", err)
	}
}

func TestLintRouteQuery(t *testing.T) {
	route := strings.Replace(goodCheck, "?v=1.2", "?rest_route=/wp/v2/users", 1)
	if issues := lintOne(route, goodFixture); len(issues) != 0 {
		t.Errorf("rest_route query: %v", issues)
	}
	up := strings.Replace(goodCheck, "?v=1.2", "?rest_route=/wp/../etc", 1)
	if issues := lintOne(up, goodFixture); len(issues) != 1 || !strings.Contains(issues[0].Message, "looks like a payload") {
		t.Errorf("traversal in query: %v", issues)
	}
}
