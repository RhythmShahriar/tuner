// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"context"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// countingPHP answers like fakePHP and counts the version queries.
func countingPHP(calls *atomic.Int32) func(context.Context, string, ...string) ([]byte, error) {
	php := fakePHP("8.1.2", nil)
	return func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls.Add(1)
		return php(ctx, name, args...)
	}
}

func TestPHPOnlyForPHPProjects(t *testing.T) {
	nextJS := map[string]string{
		"package.json":            `{"name":"shop","dependencies":{"next":"14.2.0"}}`,
		"app/page.tsx":            "export default function Page() { return null }",
		"public/robots.txt":       "User-agent: *",
		"node_modules/x/demo.php": "<?php // shipped by a package, not the app",
		"node_modules/demo.php":   "<?php",
	}
	cases := []struct {
		name     string
		files    map[string]string
		opts     Options
		wantCall bool
		source   string
	}{
		{"Next.js app", nextJS, Options{}, false, ""},
		{"WordPress", map[string]string{"wp-includes/version.php": "<?php $wp_version = '6.5';"}, Options{}, true, "php on PATH"},
		{"composer.json", map[string]string{"composer.json": "{}"}, Options{}, true, "php on PATH"},
		{"artisan", map[string]string{"artisan": "#!/usr/bin/env php"}, Options{}, true, "php on PATH"},
		{"PHP one folder down", map[string]string{"src/index.php": "<?php"}, Options{}, true, "php on PATH"},
		{"PHP two folders down only", map[string]string{"a/b/index.php": "<?php"}, Options{}, false, ""},
		{"--php on a non-PHP tree", nextJS, Options{PHP: "/usr/bin/php8.3"}, true, "--php /usr/bin/php8.3"},
		{"explicit without a path", nextJS, Options{PHPExplicit: true}, true, "php on PATH"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var calls atomic.Int32
			c.opts.Exec = countingPHP(&calls)
			res := scanTree(t, tree(t, c.files), c.opts)
			if called := calls.Load() > 0; called != c.wantCall {
				t.Fatalf("php called %d times, want called=%v", calls.Load(), c.wantCall)
			}
			fp := res.Fingerprint
			if fp.PHPSource != c.source {
				t.Errorf("php source %q, want %q", fp.PHPSource, c.source)
			}
			if !c.wantCall {
				if fp.PHP != "" || fp.Has("php") {
					t.Errorf("non-PHP tree got PHP %q, tech %v", fp.PHP, fp.Tech)
				}
				if slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "php") }) {
					t.Errorf("non-PHP tree warns about php: %v", res.Warnings)
				}
				return
			}
			if fp.PHP != "8.1.2" {
				t.Errorf("php %q", fp.PHP)
			}
		})
	}
}

func TestWPConfigLines(t *testing.T) {
	config := "<?php\n/* a block comment\n   over two lines */\n$table_prefix = 'wp_';\n" +
		"define( 'WP_DEBUG', true );\ndefine( 'AUTH_KEY', 'put your unique phrase here' );\n" +
		"define( 'FORCE_SSL_ADMIN', false );\n"
	res := scanTree(t, tree(t, map[string]string{"wp-includes/version.php": "<?php $wp_version = '6.5';", "wp-config.php": config}), Options{})
	want := map[string]string{
		"local-wp-table-prefix":    "$table_prefix = 'wp_' (line 4)",
		"local-wp-debug":           "WP_DEBUG is true (line 5)",
		"local-wp-salts":           "AUTH_KEY is the sample placeholder or empty (line 6)",
		"local-wp-force-ssl-admin": "FORCE_SSL_ADMIN is not true (line 7)",
		"local-wp-file-edit":       "DISALLOW_FILE_EDIT is not set to true",
	}
	for id, ev := range want {
		f := find(res, id)
		if f == nil {
			t.Errorf("%s missing: %v", id, ids(res))
			continue
		}
		if !slices.Contains(f.Evidence.Matched, ev) {
			t.Errorf("%s evidence %q, want %q", id, f.Evidence.Matched, ev)
		}
	}
}
