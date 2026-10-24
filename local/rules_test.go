// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/tuner/engine"
)

// ruleFixture is one file in a rule's _test.yaml.
type ruleFixture struct {
	Path    string `yaml:"path"`
	Content string `yaml:"content"`
	Pad     int    `yaml:"pad"` // filler bytes appended, for size limits
}

type ruleTests struct {
	Positive []ruleFixture `yaml:"positive"`
	Negative []ruleFixture `yaml:"negative"`
}

// TestRuleFixtures runs every built-in rule against its fixtures: each
// positive file must give the rule's finding, each negative none. A rule
// without at least one of each fails.
func TestRuleFixtures(t *testing.T) {
	rules, errs := builtinRules()
	if len(errs) > 0 {
		t.Fatalf("built-in rules: %v", errs)
	}
	if len(rules) == 0 {
		t.Fatal("no built-in rules")
	}
	tested := map[string]bool{}
	for _, r := range rules {
		t.Run(r.ID, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("rules", "tests", r.ID+"_test.yaml"))
			if err != nil {
				t.Fatalf("every rule needs rules/tests/%s_test.yaml: %v", r.ID, err)
			}
			tested[r.ID] = true
			dec := yaml.NewDecoder(bytes.NewReader(data))
			dec.KnownFields(true)
			var tests ruleTests
			if err := dec.Decode(&tests); err != nil {
				t.Fatal(err)
			}
			if len(tests.Positive) == 0 || len(tests.Negative) == 0 {
				t.Fatalf("needs at least one positive and one negative fixture (has %d and %d)", len(tests.Positive), len(tests.Negative))
			}
			for _, fx := range tests.Positive {
				f := runFixture(t, r.ID, fx)
				if f == nil {
					t.Errorf("positive %s: no finding", fx.Path)
					continue
				}
				if f.Severity == "" || f.Title == "" || f.Impact == "" || f.Fix == "" || !slices.Contains(f.Tags, "local") {
					t.Errorf("positive %s: incomplete finding %+v", fx.Path, f)
				}
				for _, ev := range f.Evidence.Matched[1:] {
					if _, snip, ok := strings.Cut(ev, ": "); ok && len(snip) > maxSnippet+len(" (line 9999)…") {
						t.Errorf("positive %s: evidence too long: %q", fx.Path, ev)
					}
				}
			}
			for _, fx := range tests.Negative {
				if f := runFixture(t, r.ID, fx); f != nil {
					t.Errorf("negative %s: %q %q", fx.Path, f.Title, f.Evidence.Matched)
				}
			}
		})
	}
	// No fixtures for a rule that doesn't exist.
	files, _ := filepath.Glob(filepath.Join("rules", "tests", "*_test.yaml"))
	for _, f := range files {
		if id := strings.TrimSuffix(filepath.Base(f), "_test.yaml"); !tested[id] {
			t.Errorf("%s has no rule", f)
		}
	}
}

// runFixture scans a tree holding just the fixture file and returns the
// rule's finding about it.
func runFixture(t *testing.T, id string, fx ruleFixture) *engine.Finding {
	t.Helper()
	body := fx.Content + strings.Repeat(" ", fx.Pad)
	res := scanTree(t, tree(t, map[string]string{fx.Path: body}), Options{Exec: noPHP})
	for i, f := range res.Findings {
		if f.ID == id {
			if f.Path != "/"+fx.Path {
				t.Errorf("%s: finding about %s", fx.Path, f.Path)
			}
			return &res.Findings[i]
		}
	}
	return nil
}

func TestRuleEvidenceIsMaskedAndShort(t *testing.T) {
	src := "<?php\n// header\n@eval(base64_decode('" + strings.Repeat("A", 200) + "')); $k = 'sk_live_" + strings.Repeat("x", 24) + "';\n"
	res := scanTree(t, tree(t, map[string]string{"x.php": src}), Options{Exec: noPHP})
	f := find(res, "local-malware-eval-base64")
	if f == nil {
		t.Fatal(ids(res))
	}
	if len(f.Evidence.Matched) != 2 {
		t.Fatalf("evidence %q", f.Evidence.Matched)
	}
	ev := f.Evidence.Matched[1]
	if !strings.HasPrefix(ev, "eval() of base64-decoded code: eval(base64_decode('AAAA") || !strings.HasSuffix(ev, "… (line 3)") {
		t.Errorf("evidence %q", ev)
	}
	// A secret on the line is masked before the snippet is cut.
	src = "<?php eval(base64_decode($x)); $k='sk_live_" + strings.Repeat("y", 24) + "';\n"
	res = scanTree(t, tree(t, map[string]string{"x.php": src}), Options{Exec: noPHP})
	b, _ := json.Marshal(find(res, "local-malware-eval-base64"))
	if strings.Contains(string(b), strings.Repeat("y", 10)) {
		t.Errorf("secret shown: %s", b)
	}
	// Control bytes are replaced. So are bidi overrides and other
	// format characters that reorder how a line shows.
	if got := snippet([]byte("a\x1b[31mb\tc"), 0); got != "a.[31mb.c" {
		t.Errorf("snippet %q", got)
	}
	if got := snippet([]byte("eval(\u202e)x(\u2066\u200b\u0085"), 0); got != "eval(.)x(..." {
		t.Errorf("snippet %q", got)
	}
}

func TestRuleExemptionsNeedTheWholeFile(t *testing.T) {
	// "<?php", then more padding than is read, then a shell: the head
	// alone looks like a "Silence is golden" index file.
	shell := "eval(base64_decode($_POST['x']));"
	root := tree(t, map[string]string{
		"wp-content/uploads/a.php":     "<?php" + strings.Repeat(" ", maxRead+10) + shell,
		"wp-content/uploads/b.php":     "<?php " + shell,
		"wp-content/uploads/index.php": "<?php // Silence is golden.",
	})
	res := scanTree(t, root, Options{Exec: noPHP})
	var paths []string
	for _, f := range res.Findings {
		if f.ID == "local-malware-php-in-uploads" {
			paths = append(paths, f.Path)
		}
	}
	slices.Sort(paths)
	if strings.Join(paths, ",") != "/wp-content/uploads/a.php,/wp-content/uploads/b.php" {
		t.Errorf("php-in-uploads about %v", paths)
	}
	for _, f := range res.Findings {
		if f.Path == "/wp-content/uploads/a.php" && !strings.Contains(strings.Join(f.Evidence.Matched, "\n"), "only the first 1 MB was read") {
			t.Errorf("evidence %q", f.Evidence.Matched)
		}
	}
}

func TestRuleLinksInUploads(t *testing.T) {
	// A link named x.php in uploads runs its target when the server
	// follows links. Its content is never read, so the "Silence is
	// golden" exemption can't clear it. A link named like media is
	// fine. Content rules don't match links they can't read.
	root := tree(t, map[string]string{
		"shell.inc":                    "<?php eval(base64_decode($_POST['x']));",
		"wp-content/uploads/index.php": "<?php // Silence is golden.",
	})
	up := filepath.Join(root, "wp-content", "uploads")
	for name, target := range map[string]string{"x.php": "../../shell.inc", "photo.jpg": "../../shell.inc", "y.php": "index.php"} {
		if err := os.Symlink(target, filepath.Join(up, name)); err != nil {
			t.Skip("no links:", err)
		}
	}
	res := scanTree(t, root, Options{Exec: noPHP})
	var paths []string
	for _, f := range res.Findings {
		switch f.ID {
		case "local-malware-php-in-uploads":
			paths = append(paths, f.Path)
			if f.Path == "/wp-content/uploads/x.php" && f.Evidence.Matched[1] != "a link to ../../shell.inc, not followed" {
				t.Errorf("evidence %q", f.Evidence.Matched)
			}
		case "local-malware-eval-base64":
			if f.Path != "/shell.inc" {
				t.Errorf("eval rule read a link: %s", f.Path)
			}
		}
	}
	slices.Sort(paths)
	if strings.Join(paths, ",") != "/wp-content/uploads/x.php,/wp-content/uploads/y.php" {
		t.Errorf("php-in-uploads about %v", paths)
	}
	if find(res, "local-malware-eval-base64") == nil {
		t.Errorf("the link's target wasn't checked: %v", ids(res))
	}
}

func TestGlobMatch(t *testing.T) {
	for _, c := range []struct {
		glob, path string
		want       bool
	}{
		{"*.php", "index.php", true},
		{"*.php", "a/index.php", false},
		{"**/*.php", "index.php", true},
		{"**/*.php", "a/b/c.php", true},
		{"**/wp-content/uploads/**/*.php", "wp-content/uploads/x.php", true},
		{"**/wp-content/uploads/**/*.php", "blog/wp-content/uploads/2024/05/x.php", true},
		{"**/wp-content/uploads/**/*.php", "wp-content/plugins/x.php", false},
		{"vendor/**", "vendor/a/b.php", true},
		{"vendor/**", "lib/vendor/a.php", false},
		{"**/.env.*", "app/.env.local", true},
		{"**/*.php[0-9]", "x.php7", true},
		{"**", "anything/at/all", true},
	} {
		if got := globMatch(c.glob, c.path); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v", c.glob, c.path, got)
		}
	}
}

func TestParseRuleErrors(t *testing.T) {
	base := "id: local-x\nname: X\nseverity: high\nconfidence: high\nfiles: ['**']\nimpact: i\nfix: f\n"
	if _, err := ParseRule([]byte(base)); err != nil {
		t.Fatalf("valid rule: %v", err)
	}
	for _, c := range []struct{ name, yaml, want string }{
		{"unknown field", base + "flavor: red\n", "field flavor not found"},
		{"bad id", strings.Replace(base, "local-x", "x", 1), "must start with local-"},
		{"bad severity", strings.Replace(base, "severity: high", "severity: huge", 1), "severity \"huge\""},
		{"bad confidence", strings.Replace(base, "confidence: high", "confidence: maybe", 1), "high or low"},
		{"no files", strings.Replace(base, "files: ['**']", "files: []", 1), "files is required"},
		{"bad glob", strings.Replace(base, "'**'", "'/etc/*'", 1), "relative path"},
		{"bad regex", base + "match:\n  regex: ['(']\n", "regex \"(\""},
		{"bad scope", base + "scope: disk\n", "project or web"},
	} {
		if _, err := ParseRule([]byte(c.yaml)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestOptionsRules(t *testing.T) {
	// A pack's rule set replaces the built-in one; broken files warn.
	pack := fstest.MapFS{
		"local-acme.yaml": {Data: []byte("id: local-acme\nname: Acme marker\nseverity: low\nconfidence: high\nfiles: ['**/*.txt']\n" +
			"match:\n  words: [acme-marker]\nimpact: i\nfix: f\n")},
		"local-acme_test.yaml": {Data: []byte("not: [a, rule")},
		"broken.yaml":          {Data: []byte("id: [")},
		"z-dup.yaml":           {Data: []byte("id: local-acme\nname: Again\nseverity: low\nconfidence: high\nfiles: ['**']\nimpact: i\nfix: f\n")},
	}
	root := tree(t, map[string]string{"a/notes.txt": "has an ACME-MARKER in it", "x.php": "<?php eval(base64_decode($x));"})
	res := scanTree(t, root, Options{Exec: noPHP, Rules: pack})
	if f := find(res, "local-acme"); f == nil || f.Evidence.Matched[1] != "Acme marker: ACME-MARKER in it (line 1)" {
		t.Errorf("findings %v", ids(res))
	}
	if find(res, "local-malware-eval-base64") != nil {
		t.Error("built-in rules ran alongside the pack's")
	}
	if !hasWarning(res, "local rules: broken.yaml: ") || !hasWarning(res, "local rules: z-dup.yaml: id local-acme is already used") {
		t.Errorf("warnings %q", res.Warnings)
	}
}

func TestRulesAreCounted(t *testing.T) {
	res := scanTree(t, tree(t, map[string]string{"index.html": "hi"}), Options{Exec: noPHP})
	// The Go stray-file checks, the rules and the session check.
	if want := len(strayChecks) + len(BuiltinRules()) + 1; res.Checks != want {
		t.Errorf("checks %d, want %d", res.Checks, want)
	}
}

func TestLiteralHints(t *testing.T) {
	for _, c := range []struct {
		re   string
		want string
	}{
		{`(?i)\beval\s*\(\s*@?\s*base64_decode\s*\(`, "[eval] [base64_decode]"},
		// The parser factors out gz; it is joined back.
		{`(?i)\b(?:gzinflate|gzuncompress|gzdecode)\s*\(`, "[gzinflate gzuncompress gzdecode]"},
		{`(?i)\b(?:wp_insert_user|wp_create_user)\s*\(`, "[wp_insert_user wp_create_user]"},
		{`(?i)\bphpinfo\s*\(`, "[phpinfo]"},
		{`(?i)['"]administrator['"]`, "[administrator]"},
		{`a.b`, ""},
		{`(x|yy)`, ""}, // too short to help
	} {
		var sets []string
		for _, set := range literalHints(c.re) {
			var words []string
			for _, w := range set {
				words = append(words, string(w))
			}
			sets = append(sets, "["+strings.Join(words, " ")+"]")
		}
		if got := strings.Join(sets, " "); got != c.want {
			t.Errorf("literalHints(%q) = %s, want %s", c.re, got, c.want)
		}
	}
}
