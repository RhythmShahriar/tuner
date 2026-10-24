// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"context"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
)

// countingRead wraps readFile and counts opens per path.
type countingRead struct {
	mu    sync.Mutex
	opens map[string]int
}

func (c *countingRead) read(path string, n int64, hs ...hash.Hash) ([]byte, int64, error) {
	c.mu.Lock()
	c.opens[path]++
	c.mu.Unlock()
	return readFile(path, n, hs...)
}

func TestWalkOpensEachFileOnce(t *testing.T) {
	// Files several checks look inside: a small phpinfo page in the web
	// root (stray files and the session check), a handler switch, a .env
	// and a .user.ini.
	root := tree(t, map[string]string{
		"info.php":          "<?php phpinfo();",
		"lib/s.php":         switchPlugin,
		".env":              "DB_PASSWORD=" + rawSecret + "\n",
		".user.ini":         "session.upload_progress.enabled = 1\n",
		"assets/app.js":     "console.log(1)",
		"debug.log":         "PHP Warning",
		"lib/deeper/x.php":  "<?php echo 1;",
		"wp-config.php.bak": "<?php define('DB_PASSWORD', 'x');",
	})
	c := &countingRead{opens: map[string]int{}}
	res := scanTree(t, root, Options{Exec: fakeSessionPHP("8.3.6", unsafeCLI("1")), read: c.read})
	for _, id := range []string{"local-phpinfo", "local-dotenv", "local-log-file", "local-wp-config-backup", sessionCheckID} {
		if find(res, id) == nil {
			t.Errorf("%s missing: %v", id, ids(res))
		}
	}
	if len(c.opens) == 0 {
		t.Fatal("the walk didn't use the read hook")
	}
	for p, n := range c.opens {
		if n > 1 {
			t.Errorf("%s opened %d times", p, n)
		}
	}
	// Files no check looks inside aren't opened at all.
	if c.opens[filepath.Join(root, "assets", "app.js")] != 0 {
		t.Error("app.js was read")
	}
}

func TestScanOpensFilesOnceExceptDetection(t *testing.T) {
	// Across the whole scan of a WordPress install, every file is opened
	// once, except the ones WordPress detection reads before the walk:
	// those at most twice.
	root := tree(t, map[string]string{
		"wp-includes/version.php":            "<?php\n$wp_version = '6.5.2';\n",
		"wp-includes/load.php":               "<?php function wp_load() {}",
		"wp-config.php":                      "<?php $table_prefix = 'x_';",
		"wp-content/plugins/a/a.php":         "<?php\n/*\nPlugin Name: A\nVersion: 1.0\n*/\n",
		"wp-content/plugins/a/inc/b.php":     "<?php echo 1;",
		"wp-content/mu-plugins/m.php":        "<?php // must-use",
		"wp-content/themes/t/style.css":      "/*\nTheme Name: T\nVersion: 2.0\n*/",
		"wp-content/themes/t/functions.php":  "<?php echo 1;",
		"wp-content/uploads/2024/05/pic.jpg": "\xff\xd8\xff",
		".env":                               "DB_PASSWORD=" + rawSecret + "\n",
	})
	c := &countingRead{opens: map[string]int{}}
	scanTree(t, root, Options{Exec: noPHP, read: c.read})
	detection := map[string]bool{}
	for _, p := range []string{"wp-includes/version.php", "wp-config.php", "wp-content/plugins/a/a.php",
		"wp-content/mu-plugins/m.php", "wp-content/themes/t/style.css"} {
		detection[filepath.Join(root, filepath.FromSlash(p))] = true
		if c.opens[filepath.Join(root, filepath.FromSlash(p))] == 0 {
			t.Errorf("%s: detection didn't go through the read hook", p)
		}
	}
	for p, n := range c.opens {
		if limit := map[bool]int{false: 1, true: 2}[detection[p]]; n > limit {
			t.Errorf("%s opened %d times", p, n)
		}
	}
	if c.opens[filepath.Join(root, "wp-includes", "load.php")] != 1 {
		t.Errorf("load.php opened %d times", c.opens[filepath.Join(root, "wp-includes", "load.php")])
	}
}

func TestWalkVisitorsKeepTheirOwnScope(t *testing.T) {
	// Laravel: stray files only under public/, the session check over
	// the whole project. bower_components is skipped by the stray-file
	// checks but not by the session check.
	root := tree(t, map[string]string{
		"artisan":                        "",
		"public/index.php":               "<?php",
		"public/backup.sql":              "INSERT",
		"storage/dump.sql":               "INSERT", // outside the web root
		"public/bower_components/x.sql":  "INSERT",
		"public/bower_components/s.php":  switchPlugin,
		"public/wp-content/cache/c.sql":  "INSERT",
		"public/wp-content/cache/s2.php": switchPlugin,
	})
	res := scanTree(t, root, Options{Exec: fakeSessionPHP("8.3.6", unsafeCLI("1"))})
	var sql []string
	for _, f := range res.Findings {
		if f.ID == "local-sql-dump" {
			sql = append(sql, f.Path)
		}
	}
	if len(sql) != 1 || sql[0] != "/public/backup.sql" {
		t.Errorf("sql dumps %v", sql)
	}
	f := find(res, sessionCheckID)
	if f == nil || !strings.Contains(strings.Join(f.Evidence.Matched, "\n"), "/public/bower_components/s.php") {
		t.Errorf("session check didn't see bower_components: %+v", f)
	}
	if strings.Contains(strings.Join(f.Evidence.Matched, "\n"), "cache") {
		t.Errorf("session check read wp-content/cache: %v", f.Evidence.Matched)
	}
}

func TestWalkStableOrder(t *testing.T) {
	files := map[string]string{}
	for i := range 40 {
		files[fmt.Sprintf("d%02d/backup.sql", i)] = "INSERT"
	}
	root := tree(t, files)
	var first []string
	for range 5 {
		got := ids(scanTree(t, root, Options{Exec: noPHP}))
		if first == nil {
			first = got
		} else if strings.Join(got, ",") != strings.Join(first, ",") {
			t.Fatalf("order changed:\n%v\n%v", first, got)
		}
	}
}

// genTree writes a WordPress-like tree of n files for the benchmark:
// mostly small PHP, some scripts and images, a few big files.
func genTree(b *testing.B, n int) string {
	b.Helper()
	root := b.TempDir()
	php := []byte("<?php\n" + strings.Repeat("// filler comment line for a typical plugin file\n$x = array( 'a' => base64_decode( $y ) );\n", 60))
	js := []byte(strings.Repeat("function f(a){return a+1}\n", 200))
	big := []byte(strings.Repeat("x", 600<<10))
	for i := range n {
		dir := filepath.Join(root, "wp-content", "plugins", fmt.Sprintf("p%03d", i/200), fmt.Sprintf("d%02d", i%200/20))
		var name string
		var body []byte
		switch {
		case i%500 == 0:
			name, body = fmt.Sprintf("big%d.php", i), big
		case i%4 == 3:
			name, body = fmt.Sprintf("s%d.js", i), js
		case i%10 == 9:
			name, body = fmt.Sprintf("i%d.png", i), []byte("\x89PNG\r\n\x1a\n")
		default:
			name, body = fmt.Sprintf("f%d.php", i), php
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			b.Fatal(err)
		}
	}
	return root
}

// BenchmarkScan scans a generated 20,000-file tree. For reference, on a
// 16-thread i9-9900K with a warm page cache one scan takes about 0.45 s:
// about 0.2 s for the single walk and its workers, the rest for the 17
// built-in rules. The two serial walks it replaced took about 0.45 s
// without any rules.
func BenchmarkScan(b *testing.B) {
	root := genTree(b, 20_000)
	opts := Options{Exec: noPHP}
	b.ResetTimer()
	for b.Loop() {
		if _, err := Scan(context.Background(), root, opts, engine.Hooks{}); err != nil {
			b.Fatal(err)
		}
	}
}

func TestWalkSkipDirs(t *testing.T) {
	// A WordPress in /blog that --discover scans on its own: the parent's
	// walk leaves it out, so its findings aren't reported twice.
	root := tree(t, map[string]string{
		"shell.php":      "<?php eval(base64_decode($x));",
		"blog/shell.php": "<?php eval(base64_decode($x));",
		"blog/dump.sql":  "INSERT",
	})
	paths := func(res *engine.Result) []string {
		var out []string
		for _, f := range res.Findings {
			out = append(out, f.ID+" "+f.Path)
		}
		return out
	}
	all := paths(scanTree(t, root, Options{Exec: noPHP}))
	if len(all) != 3 {
		t.Fatalf("without SkipDirs: %v", all)
	}
	for _, skip := range []string{filepath.Join(root, "blog"), "blog"} {
		got := paths(scanTree(t, root, Options{Exec: noPHP, SkipDirs: []string{skip}}))
		if strings.Join(got, ",") != "local-malware-eval-base64 /shell.php" {
			t.Errorf("SkipDirs %q: %v", skip, got)
		}
	}
	// The root itself is never skipped.
	if got := paths(scanTree(t, root, Options{Exec: noPHP, SkipDirs: []string{root}})); len(got) != 3 {
		t.Errorf("root skipped: %v", got)
	}
}
