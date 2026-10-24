// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
)

// fakeSessionPHP answers both php queries a local scan makes: the version
// and the session settings (nil cfg means php can't report them).
func fakeSessionPHP(version string, cfg map[string]any) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, _ string, args ...string) ([]byte, error) {
		switch {
		case slices.Equal(args, []string{"-n", "-r", "echo PHP_VERSION;"}):
			return []byte(version), nil
		case len(args) > 0 && args[len(args)-1] == phpSessionQuery:
			if !slices.Contains(args, "auto_prepend_file=") || !slices.Contains(args, "auto_append_file=") {
				return nil, errors.New("session query must clear auto_prepend_file and auto_append_file")
			}
			if cfg == nil {
				return nil, exec.ErrNotFound
			}
			b, _ := json.Marshal(cfg)
			return b, nil
		}
		return nil, errors.New("unexpected php args")
	}
}

const switchPlugin = `<?php
/* Plugin Name: Legacy Sessions */
ini_set('session.serialize_handler', 'php');
session_start();
`

func sessionScan(t *testing.T, files map[string]string, cfg map[string]any, configRoot string) *engine.Finding {
	t.Helper()
	root := tree(t, files)
	res := scanTree(t, root, Options{Exec: fakeSessionPHP("8.3.6", cfg), ConfigRoot: configRoot})
	return find(res, sessionCheckID)
}

func unsafeCLI(progress string) map[string]any {
	return map[string]any{"ini": "/etc/php.ini", "scanned": false, "handler": "php_serialize", "progress": progress}
}

func TestSessionReachable(t *testing.T) {
	f := sessionScan(t, map[string]string{"wp-content/plugins/legacy/legacy.php": switchPlugin}, unsafeCLI("1"), t.TempDir())
	if f == nil {
		t.Fatal("no finding")
	}
	if f.Severity != engine.High || f.Confidence != "high" || !strings.Contains(f.Title, "reachable: all four") {
		t.Errorf("got %s/%s %q", f.Severity, f.Confidence, f.Title)
	}
	ev := strings.Join(f.Evidence.Matched, "\n")
	for _, want := range []string{"✓ session.serialize_handler = php_serialize", "✓ switched to php", "legacy.php:3", "✓ before session_start() (same file, line 4)", "✓ session.upload_progress.enabled is on"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence lacks %q:\n%s", want, ev)
		}
	}
	if !strings.Contains(f.Fix, "session.upload_progress.enabled = 0") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestSessionQuietWithoutSwitch(t *testing.T) {
	for name, src := range map[string]string{
		"no switch":       "<?php session_start();",
		"commented out":   "<?php\n// ini_set('session.serialize_handler', 'php');\n/* ini_set('session.serialize_handler', 'php'); */\n# ini_set('session.serialize_handler','php');\nsession_start();",
		"in a string":     "<?php $doc = \"call ini_set('session.serialize_handler', 'php'); first\";",
		"switch to safe":  "<?php ini_set('session.serialize_handler', 'php_serialize'); session_start();",
		"other ini value": "<?php ini_set('session.gc_maxlifetime', 'php'); session_start();",
	} {
		if f := sessionScan(t, map[string]string{"app.php": src}, unsafeCLI("1"), t.TempDir()); f != nil {
			t.Errorf("%s: unexpected finding %q", name, f.Title)
		}
	}
}

func TestSessionMitigated(t *testing.T) {
	f := sessionScan(t, map[string]string{"app.php": switchPlugin}, unsafeCLI("0"), t.TempDir())
	if f == nil || f.Severity != engine.Info || !strings.Contains(f.Title, "mitigated") {
		t.Fatalf("got %+v", f)
	}
}

func TestSessionNotReachableWithPHPHandler(t *testing.T) {
	cfg := map[string]any{"ini": false, "scanned": false, "handler": "php", "progress": "1"}
	f := sessionScan(t, map[string]string{"app.php": switchPlugin}, cfg, t.TempDir())
	if f == nil || f.Severity != engine.Low || !strings.Contains(f.Title, "not reachable now") {
		t.Fatalf("got %+v", f)
	}
}

func TestSessionConfigUnknown(t *testing.T) {
	f := sessionScan(t, map[string]string{"app.php": switchPlugin}, nil, t.TempDir())
	if f == nil || f.Severity != engine.Medium || f.Confidence != "low" || !strings.Contains(f.Title, "configuration unknown") {
		t.Fatalf("got %+v", f)
	}
}

func TestSessionLikely(t *testing.T) {
	cases := map[string]string{
		"computed value":       "<?php ini_set('session.serialize_handler', $handler); session_start();",
		"start in other file":  "<?php ini_set('session.serialize_handler', 'php');",
		"start before":         "<?php session_start();\nini_set('session.serialize_handler', 'php');",
		"ini_alter, uppercase": "<?php INI_ALTER(\"session.serialize_handler\", \"php\");",
	}
	for name, src := range cases {
		f := sessionScan(t, map[string]string{"app.php": src}, unsafeCLI("1"), t.TempDir())
		if f == nil || f.Severity != engine.High || f.Confidence != "low" || !strings.Contains(f.Title, "likely reachable") {
			t.Errorf("%s: got %+v", name, f)
		}
	}
}

func TestSessionHandlerSetInCode(t *testing.T) {
	cfg := map[string]any{"ini": false, "scanned": false, "handler": "php", "progress": "1"}
	src := "<?php\nini_set('session.serialize_handler', 'php_binary');\nini_set('session.serialize_handler', 'php');\nsession_start();"
	f := sessionScan(t, map[string]string{"app.php": src}, cfg, t.TempDir())
	if f == nil || f.Severity != engine.High || !strings.Contains(strings.Join(f.Evidence.Matched, "\n"), "set to php_binary in code (/app.php:2)") {
		t.Fatalf("got %+v", f)
	}
}

// On Debian and Ubuntu the web server's settings live next to the CLI's.
// They win: here the CLI is safe but the FPM pool isn't.
func TestSessionDebianFPMPool(t *testing.T) {
	etc := tree(t, map[string]string{
		"etc/php/8.3/cli/php.ini":           "session.serialize_handler = php\n",
		"etc/php/8.3/fpm/php.ini":           "[Session]\nsession.serialize_handler = php\nsession.upload_progress.enabled = On\n",
		"etc/php/8.3/fpm/conf.d/10-x.ini":   "; nothing here\n",
		"etc/php/8.3/fpm/pool.d/www.conf":   "[www]\nphp_admin_value[session.serialize_handler] = php_serialize\n",
		"etc/php/8.3/fpm/pool.d/other.conf": "[other]\nphp_admin_flag[session.upload_progress.enabled] = off\n",
	})
	cfg := map[string]any{"ini": "/etc/php/8.3/cli/php.ini", "scanned": false, "handler": "php", "progress": "1"}
	f := sessionScan(t, map[string]string{"app.php": switchPlugin}, cfg, etc)
	if f == nil || f.Severity != engine.High {
		t.Fatalf("got %+v", f)
	}
	if ev := strings.Join(f.Evidence.Matched, "\n"); !strings.Contains(ev, "php_serialize (/etc/php/8.3/fpm/pool.d/www.conf)") && !strings.Contains(ev, "pool.d/www.conf") {
		t.Errorf("evidence should name the pool:\n%s", ev)
	}

	// With upload progress off in every pool, it's mitigated even though
	// the CLI has it on.
	etc2 := tree(t, map[string]string{
		"etc/php/8.3/cli/php.ini":         "",
		"etc/php/8.3/fpm/php.ini":         "session.serialize_handler = php_serialize\nsession.upload_progress.enabled = 0 ; CVE-2026-115560\n",
		"etc/php/8.3/fpm/pool.d/www.conf": "[www]\n",
	})
	if f := sessionScan(t, map[string]string{"app.php": switchPlugin}, cfg, etc2); f == nil || f.Severity != engine.Info {
		t.Errorf("all pools off should be mitigated, got %+v", f)
	}
}

func TestSessionRootUserIniOverride(t *testing.T) {
	files := map[string]string{"app.php": switchPlugin, ".user.ini": "session.upload_progress.enabled = 0\n"}
	if f := sessionScan(t, files, unsafeCLI("1"), t.TempDir()); f == nil || f.Severity != engine.Info {
		t.Errorf("a root .user.ini turning it off covers the site, got %+v", f)
	}
	files = map[string]string{"app.php": switchPlugin, "sub/.user.ini": "session.upload_progress.enabled = 0\n"}
	if f := sessionScan(t, files, unsafeCLI("1"), t.TempDir()); f == nil || f.Severity != engine.High {
		t.Errorf("a .user.ini in a subfolder only covers that folder, got %+v", f)
	}
	files = map[string]string{"app.php": switchPlugin, ".htaccess": "php_value session.serialize_handler php_binary\n"}
	cfg := map[string]any{"ini": false, "scanned": false, "handler": "php", "progress": "1"}
	if f := sessionScan(t, files, cfg, t.TempDir()); f == nil || f.Severity != engine.High {
		t.Errorf(".htaccess setting php_binary meets condition 1, got %+v", f)
	}
}

func TestStripPHPComments(t *testing.T) {
	src := "<?php\n$a = 'x // not a comment'; // gone\n/* gone\n gone */ $b = \"# kept\"; # gone\necho 1; ?>tail"
	got := string(stripPHPComments([]byte(src)))
	for _, keep := range []string{"'x // not a comment'", `"# kept"`, "echo 1; ?>tail"} {
		if !strings.Contains(got, keep) {
			t.Errorf("lost %q:\n%s", keep, got)
		}
	}
	if strings.Contains(got, "gone") {
		t.Errorf("comment kept:\n%s", got)
	}
	if strings.Count(got, "\n") != strings.Count(src, "\n") {
		t.Error("line count changed")
	}
}

// Only the code between PHP tags is tokenized: quotes in HTML don't open
// strings; heredocs, nowdocs and comments hide what they contain.
func TestFindSwitchesTemplates(t *testing.T) {
	call := "ini_set('session.serialize_handler','php'); session_start();"
	cases := []struct {
		name, src string
		want      int // switches found
	}{
		{"plain HTML before", "<p>Do not miss it</p>\n<?php " + call, 1},
		{"apostrophe in HTML", "<p>Don't miss it</p>\n<?php " + call, 1},
		{"quote in HTML between blocks", "<?php $a = 1; ?><a title=\"x>Don't\n<?php " + call, 1},
		{"short echo tag", "<p>it's</p><?= ini_set('session.serialize_handler', 'php') ?><?php session_start();", 1},
		{"uppercase open tag", "it's\n<?PHP\n" + call, 1},
		{"after a closed block", "<?php echo 'a'; ?>\n<b>'</b>\n<?php\n" + call, 1},
		{"?> ends a // comment", "<?php // note ?><p>it's</p><?php " + call, 1},
		{"?> ends a # comment", "<?php # note ?>'<?php " + call, 1},
		{"attribute isn't a comment", "<?php #[Attr] " + call, 1},
		{"heredoc then code", "<?php $s = <<<EOT\nit's\nEOT;\n" + call, 1},
		{"flexible heredoc close", "<?php f(<<<\"EOT\"\n    it's\n    EOT, 1);\n" + call, 1},
		{"nowdoc then code", "<?php $s = <<<'EOT'\n\"\nEOT;\n" + call, 1},

		{"call text in HTML", "<p>Use " + call + " to switch.</p>", 0},
		{"call text in a heredoc", "<?php $help = <<<EOT\n" + call + "\nEOT;\n", 0},
		{"call text in a nowdoc", "<?php $help = <<<'EOT'\n" + call + "\n  EOT;\n", 0},
		{"heredoc id must end", "<?php $s = <<<EOT\nEOTX " + call + "\nEOT;\n", 0},
		{"call in a block comment", "<?php /* ?> " + call + " */", 0},
		{"call in a line comment", "<?php // " + call, 0},
		{"<?xml isn't PHP", "<?xml version=\"1.0\"?>\n" + call, 0},
		{"no PHP tags", call, 0},
	}
	for _, c := range cases {
		got := findSwitches("/x.php", []byte(c.src))
		if len(got) != c.want {
			t.Errorf("%s: %d switches, want %d", c.name, len(got), c.want)
		}
		if c.want > 0 && len(got) > 0 && got[0].startLine == 0 && !strings.Contains(c.name, "short echo") {
			t.Errorf("%s: session_start() not seen after the switch", c.name)
		}
	}
}

// A theme template with an apostrophe in its HTML, end to end.
func TestSessionApostropheInTemplate(t *testing.T) {
	src := "<p>Don't miss it</p>\n<?php ini_set('session.serialize_handler','php'); session_start();"
	if f := sessionScan(t, map[string]string{"wp-content/themes/t/header.php": src}, unsafeCLI("1"), t.TempDir()); f == nil || f.Severity != engine.High {
		t.Errorf("got %+v", f)
	}
}
