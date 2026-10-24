// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
	"github.com/RhythmShahriar/tuner/vulns"
)

const rawSecret = "supersecret-db-pass"

// tree writes files (path → content) under a new temp dir.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(p, "/") {
			continue
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// fakePHP answers like `php -n -r 'echo PHP_VERSION;'`.
func fakePHP(out string, err error) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		if !slices.Equal(args, []string{"-n", "-r", "echo PHP_VERSION;"}) {
			return nil, errors.New("unexpected args")
		}
		return []byte(out), err
	}
}

var noPHP = fakePHP("", exec.ErrNotFound)

func scanTree(t *testing.T, root string, opts Options) *engine.Result {
	t.Helper()
	if opts.Exec == nil && opts.PHP == "" {
		opts.Exec = fakePHP("8.3.6", nil)
	}
	res, err := Scan(context.Background(), root, opts, engine.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func ids(res *engine.Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.ID+" "+f.Path)
	}
	return out
}

func find(res *engine.Result, id string) *engine.Finding {
	for i := range res.Findings {
		if res.Findings[i].ID == id {
			return &res.Findings[i]
		}
	}
	return nil
}

const hardenedConfig = `<?php
define( 'DB_NAME', 'site' );
define( 'DB_PASSWORD', 'Zx81-unique-pass' );
define( 'AUTH_KEY',         'k1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' );
define( 'SECURE_AUTH_KEY',  'k2-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' );
define( 'LOGGED_IN_KEY',    'k3-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' );
define( 'NONCE_KEY',        'k4-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' );
define( 'AUTH_SALT',        'k5-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' );
define( 'SECURE_AUTH_SALT', 'k6-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' );
define( 'LOGGED_IN_SALT',   'k7-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' );
define( 'NONCE_SALT',       'k8-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' );
$table_prefix = 'x7f_';
// define( 'WP_DEBUG', true );
/* define( 'WP_DEBUG', true ); */
define( 'WP_DEBUG', false );
define( 'DISALLOW_FILE_EDIT', true );
define( 'FORCE_SSL_ADMIN', true );
if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', __DIR__ . '/' ); }
require_once ABSPATH . 'wp-settings.php';
`

const sampleConfig = `<?php
define( 'DB_PASSWORD', '` + rawSecret + `' );
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
define( 'NONCE_KEY',        'put your unique phrase here' );
define( 'AUTH_SALT',        'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT',   'put your unique phrase here' );
define( 'NONCE_SALT',       'put your unique phrase here' );
$table_prefix = 'wp_';
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
require_once ABSPATH . 'wp-settings.php';
`

// wpSite is a WordPress root with a plugin, a theme and a must-use plugin.
func wpSite(config string) map[string]string {
	return map[string]string{
		"index.php":                    "<?php require __DIR__ . '/wp-blog-header.php';",
		"wp-includes/version.php":      "<?php\n$wp_version = '6.4.1';\n$wp_db_version = 56657;\n",
		"wp-config.php":                config,
		"wp-config-sample.php":         sampleConfig,
		"wp-content/index.php":         "<?php // Silence is golden.",
		"wp-content/plugins/index.php": "<?php // Silence is golden.",
		// Main file not named after the folder; a helper file comes first.
		"wp-content/plugins/contact-form-7/includes.php":          "<?php // no header here",
		"wp-content/plugins/contact-form-7/wp-contact-form-7.php": "<?php\n/**\n * Plugin Name: Contact Form 7\n * Version: 5.3.1\n * Requires PHP: 7.4\n */\n",
		"wp-content/plugins/contact-form-7/readme.txt":            "Stable tag: 9.9\n",
		"wp-content/plugins/hello.php":                            "<?php\n/*\nPlugin Name: Hello Dolly\nVersion: 1.7.2\n*/\n",
		"wp-content/plugins/not-a-plugin/lib.php":                 "<?php // nothing",
		"wp-content/themes/twentytwenty/style.css":                "/*\nTheme Name: Twenty Twenty\nVersion: 2.1\n*/\n",
		"wp-content/themes/broken/readme.txt":                     "no style.css",
		"wp-content/mu-plugins/host.php":                          "<?php\n/* Plugin Name: Host cache\n Version: 3.0 */\n",
		// Ordinary content that must not be reported.
		"wp-content/uploads/2024/01/photo.jpg":         "jpg",
		"wp-content/uploads/2024/01/backup.zip":        "media library upload",
		"wp-content/plugins/contact-form-7/demo.zip":   "shipped by the plugin",
		"wp-content/plugins/contact-form-7/info.php":   "<?php phpinfo(); // plugin diagnostics",
		"wp-content/plugins/contact-form-7/schema.sql": "CREATE TABLE x;",
		"node_modules/pkg/.env":                        "TOKEN=" + rawSecret,
		"vendor/pkg/backup.sql":                        "-- vendored",
		".env.example":                                 "DB_PASSWORD=changeme",
		"about.php":                                    "<?php echo 'hello';",
	}
}

func TestWordPressFingerprint(t *testing.T) {
	root := tree(t, wpSite(hardenedConfig))
	var got fingerprint.Result
	res, err := Scan(context.Background(), root, Options{Exec: fakePHP("8.3.6", nil)},
		engine.Hooks{Fingerprint: func(fp fingerprint.Result) { got = fp }})
	if err != nil {
		t.Fatal(err)
	}
	fp := res.Fingerprint
	if got.String() != fp.String() || fp.String() != "WordPress 6.4.1 · PHP 8.3.6" || fp.PHPBuild != "" {
		t.Errorf("fingerprint %q (hook saw %q), build %q", fp, got, fp.PHPBuild)
	}
	want := []fingerprint.Component{
		{Type: "plugin", Slug: "contact-form-7", Version: "5.3.1", Source: "plugin header"},
		{Type: "plugin", Slug: "hello", Version: "1.7.2", Source: "plugin header"},
		{Type: "theme", Slug: "twentytwenty", Version: "2.1", Source: "style.css"},
	}
	if !slices.Equal(fp.Components, want) {
		t.Errorf("components\n got %+v\nwant %+v", fp.Components, want)
	}
	if res.Target != root || res.Score != engine.Score(res.Findings) {
		t.Errorf("target %q score %d", res.Target, res.Score)
	}

	// Negative: a hardened config and clean tree leave only the mu-plugins note.
	if got := ids(res); !slices.Equal(got, []string{"local-wp-mu-plugins /wp-content/mu-plugins"}) {
		t.Errorf("clean site findings: %v", got)
	}
	if mu := find(res, "local-wp-mu-plugins"); mu == nil || mu.Evidence.Matched[0] != "host.php (Host cache 3.0)" {
		t.Errorf("mu-plugins: %+v", mu)
	}
}

func TestWPConfig(t *testing.T) {
	root := tree(t, wpSite(sampleConfig))
	if err := os.Chmod(filepath.Join(root, "wp-config.php"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := scanTree(t, root, Options{})
	want := map[string]engine.Severity{
		"local-wp-salts":           engine.Medium,
		"local-wp-debug":           engine.Medium,
		"local-wp-file-edit":       engine.Low,
		"local-wp-table-prefix":    engine.Info,
		"local-wp-force-ssl-admin": engine.Info,
	}
	if runtime.GOOS != "windows" {
		want["local-wp-config-perms"] = engine.Low
	}
	for id, sev := range want {
		f := find(res, id)
		if f == nil {
			t.Errorf("%s missing; got %v", id, ids(res))
			continue
		}
		if f.Severity != sev || f.Path != "/wp-config.php" || f.Confidence != "high" ||
			f.URL != "file://"+filepath.ToSlash(root)+"/wp-config.php" || f.Target != root {
			t.Errorf("%s: %+v", id, f)
		}
	}
	if f := find(res, "local-wp-debug"); !strings.Contains(strings.Join(f.Evidence.Matched, "\n"), "wp-content/debug.log") {
		t.Errorf("debug evidence: %v", f.Evidence.Matched)
	}
	if f := find(res, "local-wp-salts"); len(f.Evidence.Matched) != 8 {
		t.Errorf("salts evidence: %v", f.Evidence.Matched)
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), rawSecret) || strings.Contains(string(b), "put your unique") {
		t.Error("report leaks wp-config values")
	}
}

func TestWPConfigVariants(t *testing.T) {
	cases := []struct {
		name, config string
		want         map[string]engine.Severity // id → severity; absent ids must not fire
		lowConf      []string
	}{
		{"debug hidden from visitors",
			"<?php define('WP_DEBUG', 1); define('WP_DEBUG_DISPLAY', false); define('WP_DEBUG_LOG', '/var/log/wp.log');" +
				"define('DISALLOW_FILE_MODS', true); define('FORCE_SSL_ADMIN', 'yes');",
			map[string]engine.Severity{"local-wp-debug": engine.Low, "local-wp-salts": engine.Medium}, nil},
		{"string false is truthy in PHP",
			`<?php define("WP_DEBUG", "false"); define('DISALLOW_FILE_EDIT', true); define('FORCE_SSL_ADMIN', true);`,
			map[string]engine.Severity{"local-wp-debug": engine.Medium, "local-wp-salts": engine.Medium}, nil},
		{"computed values aren't judged",
			"<?php define('WP_DEBUG', getenv('WP_DEBUG') === 'on'); define('AUTH_KEY', getenv('AUTH_KEY'));" +
				"define('DISALLOW_FILE_EDIT', true); define('FORCE_SSL_ADMIN', true);",
			map[string]engine.Severity{"local-wp-salts": engine.Medium}, nil},
		{"settings may live in an included file",
			"<?php require_once __DIR__ . '/config/application.php';\nrequire_once ABSPATH . 'wp-settings.php';",
			map[string]engine.Severity{"local-wp-salts": engine.Medium, "local-wp-file-edit": engine.Low, "local-wp-force-ssl-admin": engine.Info},
			[]string{"local-wp-salts", "local-wp-file-edit", "local-wp-force-ssl-admin"}},
		{"duplicate keys", strings.Replace(hardenedConfig, "k2-", "k1-", 1),
			map[string]engine.Severity{"local-wp-salts": engine.Medium}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := scanTree(t, tree(t, map[string]string{"wp-includes/version.php": "<?php $wp_version = '6.5';", "wp-config.php": c.config}), Options{})
			for _, f := range res.Findings {
				if !strings.HasPrefix(f.ID, "local-wp-") || f.ID == "local-wp-config-perms" {
					continue
				}
				sev, ok := c.want[f.ID]
				if !ok || sev != f.Severity {
					t.Errorf("%s %s fired; want %v", f.ID, f.Severity, c.want)
				}
				if low := f.Confidence == "low"; low != slices.Contains(c.lowConf, f.ID) {
					t.Errorf("%s confidence %s", f.ID, f.Confidence)
				}
			}
			for id := range c.want {
				if find(res, id) == nil {
					t.Errorf("%s missing: %v", id, ids(res))
				}
			}
		})
	}
}

func TestWPConfigOneLevelUp(t *testing.T) {
	parent := tree(t, map[string]string{
		"wp-config.php":                  "<?php define('WP_DEBUG', true);",
		"public/wp-includes/version.php": "<?php $wp_version = '6.5';",
	})
	res := scanTree(t, filepath.Join(parent, "public"), Options{})
	if f := find(res, "local-wp-debug"); f == nil || f.Path != filepath.ToSlash(filepath.Join(parent, "wp-config.php")) {
		t.Errorf("wp-config.php above the root: %+v", f)
	}

	// Missing entirely: a warning, not an error.
	res = scanTree(t, tree(t, map[string]string{"wp-includes/version.php": "<?php $wp_version = '6.5';"}), Options{})
	if !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "wp-config.php not found") }) {
		t.Errorf("warnings: %v", res.Warnings)
	}
}

func TestStrayFiles(t *testing.T) {
	files := wpSite(hardenedConfig)
	for p, body := range map[string]string{
		".env":               "APP_KEY=x\nDB_PASSWORD=" + rawSecret + "\n",
		".env.production":    "APP_NAME=shop\n",
		"wp-config.php.bak":  sampleConfig,
		".wp-config.php.swp": "swap",
		"wp-config.old":      "old",
		"wp-content/themes/twentytwenty/functions.php~": "<?php",
		"backup.sql":                        "INSERT INTO wp_users ...",
		"db/site-2024.sql.gz":               "gz",
		"site-backup.tar.gz":                "tgz",
		"anything.zip":                      "top-level archives count",
		"wp-content/ai1wm-backups/x.wpress": "wpress",
		"wp-content/debug.log":              "PHP Notice: ... token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"error_log":                         "PHP Warning",
		"phpinfo.php":                       "<?php phpinfo(); ?>",
		"tools/info.php":                    "<?php\nphpinfo ( INFO_ALL );",
		"adminer-4.8.1.php":                 "<?php /* adminer */",
		"phpmyadmin/index.php":              "<?php",
		".git/HEAD":                         "ref: refs/heads/main",
		".git/config":                       "[core]",
		"auth.json":                         `{"github-oauth":{"github.com":"ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}`,
		"certs/server.key":                  "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAzzzzzzzzzzzzzzzzzzzzzzzz\n-----END RSA PRIVATE KEY-----",
		"certs/public.pem":                  "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
	} {
		files[p] = body
	}
	root := tree(t, files)
	res := scanTree(t, root, Options{})

	want := map[string]engine.Severity{
		"local-dotenv /.env":                                              engine.High,
		"local-dotenv /.env.production":                                   engine.Medium,
		"local-wp-config-backup /wp-config.php.bak":                       engine.High,
		"local-wp-config-backup /.wp-config.php.swp":                      engine.High,
		"local-wp-config-backup /wp-config.old":                           engine.High,
		"local-php-backup /wp-content/themes/twentytwenty/functions.php~": engine.Medium,
		"local-sql-dump /backup.sql":                                      engine.High,
		"local-sql-dump /db/site-2024.sql.gz":                             engine.High,
		"local-backup-archive /site-backup.tar.gz":                        engine.High,
		"local-backup-archive /anything.zip":                              engine.High,
		"local-backup-archive /wp-content/ai1wm-backups/x.wpress":         engine.High,
		"local-log-file /wp-content/debug.log":                            engine.Medium,
		"local-log-file /error_log":                                       engine.Medium,
		"local-phpinfo /phpinfo.php":                                      engine.Medium,
		"local-phpinfo /tools/info.php":                                   engine.Medium,
		"local-db-admin /adminer-4.8.1.php":                               engine.Medium,
		"local-db-admin /phpmyadmin":                                      engine.Medium,
		"local-vcs-dir /.git":                                             engine.Medium,
		"local-composer-auth /auth.json":                                  engine.High,
		"local-private-key /certs/server.key":                             engine.High,
		"local-wp-mu-plugins /wp-content/mu-plugins":                      engine.Info,
	}
	got := map[string]engine.Severity{}
	for _, f := range res.Findings {
		got[f.ID+" "+f.Path] = f.Severity
	}
	for k, sev := range want {
		if got[k] != sev {
			t.Errorf("%s: got %q, want %s", k, got[k], sev)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected finding %s", k) // negatives: templates, plugin files, media, vendor, node_modules
		}
	}

	// Secrets are found and only ever masked.
	if f := find(res, "local-dotenv"); f.Path != "/.env" || len(f.Evidence.Secrets) == 0 || f.Evidence.Secrets[0].Name != "DB_PASSWORD" {
		t.Errorf(".env secrets: %+v", f)
	}
	b, _ := json.Marshal(res)
	for _, raw := range []string{rawSecret, "ghp_aaaaaaaaaaaaaaaaaaaa", "ghp_bbbbbbbbbbbbbbbbbbbb", "MIIEowIBAAKCAQEA"} {
		if strings.Contains(string(b), raw) {
			t.Errorf("report leaks %q", raw)
		}
	}
}

func TestLaravel(t *testing.T) {
	root := tree(t, map[string]string{
		"artisan":          "#!/usr/bin/env php",
		".env":             "APP_ENV=production\nAPP_DEBUG=true # temporary\nDB_PASSWORD=" + rawSecret + "\n",
		"public/index.php": "<?php require __DIR__.'/../vendor/autoload.php';",
		"public/.env":      "DB_PASSWORD=" + rawSecret,
		"backup.sql":       "outside the document root",
		".git/HEAD":        "ref",
		"composer.lock":    `{"packages":[{"name":"laravel/framework","version":"v10.0.0"}]}`,
	})
	res := scanTree(t, root, Options{})
	if fp := res.Fingerprint; !fp.Has("laravel") || !fp.Has("php") || fp.Has("wordpress") {
		t.Errorf("fingerprint %+v", fp)
	}
	got := ids(res)
	want := []string{"local-dotenv /public/.env", "local-laravel-debug /.env"}
	if !slices.Equal(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
	if f := find(res, "local-laravel-debug"); f.Severity != engine.Medium || !slices.Contains(f.Evidence.Matched, "APP_ENV=production") {
		t.Errorf("laravel debug: %+v", f)
	}

	// Negative: debug off.
	os.WriteFile(filepath.Join(root, ".env"), []byte("APP_DEBUG=false\n"), 0o600)
	if res := scanTree(t, root, Options{}); find(res, "local-laravel-debug") != nil {
		t.Error("APP_DEBUG=false reported")
	}
}

func TestPHPVersion(t *testing.T) {
	root := tree(t, map[string]string{"index.php": "<?php"})
	cases := []struct {
		name, php, out string
		err            error
		version, build string
		warning        string
	}{
		{"plain", "", "8.3.6", nil, "8.3.6", "", ""},
		{"distro build", "", "8.1.2-1ubuntu2.19\n", nil, "8.1.2", "8.1.2-1ubuntu2.19", ""},
		{"not installed", "", "", exec.ErrNotFound, "", "", "php not found on PATH"},
		{"chosen binary missing", "/opt/php9", "", exec.ErrNotFound, "", "", "couldn't read the PHP version from /opt/php9"},
		{"fails", "", "", errors.New("exit status 255"), "", "", "exit status 255"},
		{"garbage", "", "Could not open input file\n<script>", nil, "", "", "unexpected output"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := scanTree(t, root, Options{PHP: c.php, Exec: fakePHP(c.out, c.err)})
			fp := res.Fingerprint
			if fp.PHP != c.version || fp.PHPBuild != c.build || fp.Has("php") != (c.version != "") {
				t.Errorf("php %q build %q tech %v", fp.PHP, fp.PHPBuild, fp.Tech)
			}
			hasWarn := slices.ContainsFunc(res.Warnings, func(w string) bool { return c.warning != "" && strings.Contains(w, c.warning) })
			if hasWarn != (c.warning != "") || (c.warning == "" && len(res.Warnings) > 0) {
				t.Errorf("warnings %q, want %q", res.Warnings, c.warning)
			}
		})
	}
}

// TestPHPBinary runs a real (fake) php executable, checking it gets the
// version query and nothing else.
func TestPHPBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script")
	}
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	bin := filepath.Join(dir, "php8.3")
	script := "#!/bin/sh\nprintf '%s|' \"$@\" > '" + argsFile + "'\necho 8.3.12\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test executable
		t.Fatal(err)
	}
	res := scanTree(t, tree(t, map[string]string{"index.php": "<?php"}), Options{PHP: bin})
	if res.Fingerprint.PHP != "8.3.12" {
		t.Fatalf("php %q, warnings %v", res.Fingerprint.PHP, res.Warnings)
	}
	if b, _ := os.ReadFile(argsFile); string(b) != "-n|-r|echo PHP_VERSION;|" {
		t.Errorf("php ran with %q", b)
	}
}

// fakeVulnAPI serves WPVulnerability and wordpress.org shaped answers.
func fakeVulnAPI(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/plugin/contact-form-7/":
			w.Write([]byte(`{"error":0,"data":{"name":"Contact Form 7","closed":0,"vulnerability":[{"uuid":"u1",
				"operator":{"max_version":"5.3.2","max_operator":"lt","unfixed":"0"},
				"source":[{"id":"CVE-2020-35489","name":"CVE-2020-35489","link":"https://www.cve.org/x"}],
				"impact":{"cvss3":{"score":"10.0","severity":"critical"},"kev":false}}]}}`))
		case "/php/8.1.2/":
			w.Write([]byte(`{"error":0,"data":{"name":"PHP 8.1","date_end":"2025-12-31","vulnerability":[]}}`))
		case "/plugins/info/1.2/", "/themes/info/1.2/":
			w.Write([]byte(`{"error":"not found"}`))
		case "/core/version-check/1.7/":
			w.Write([]byte(`{"offers":[{"current":"6.4.1"}]}`))
		default:
			w.Write([]byte(`{"error":0,"data":{"vulnerability":[]}}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAdvisor(t *testing.T) {
	api := fakeVulnAPI(t)
	adv := &vulns.Advisor{Client: &vulns.Client{HTTP: api.Client(), VulnBase: api.URL, WPOrgBase: api.URL, Pace: -1}}
	root := tree(t, wpSite(hardenedConfig))
	res := scanTree(t, root, Options{Exec: fakePHP("8.1.2-1ubuntu2.19", nil), Advisor: adv})

	f := find(res, "vuln-plugin-contact-form-7")
	if f == nil {
		t.Fatalf("no plugin vuln: %v %v", ids(res), res.Warnings)
	}
	if f.Severity != engine.Critical || f.Target != root || f.Path != "/wp-content/plugins/contact-form-7/" ||
		f.URL != "file://"+filepath.ToSlash(root)+"/wp-content/plugins/contact-form-7/" {
		t.Errorf("plugin vuln: %+v", f)
	}
	// The machine's PHP goes through the same matching, distro caveat included.
	if f := find(res, "php-eol"); f == nil || f.Confidence != "low" {
		t.Errorf("php-eol: %+v", f)
	}
	if res.Score != engine.Score(res.Findings) || res.Score >= 100 {
		t.Errorf("score %d", res.Score)
	}
}

func TestSelect(t *testing.T) {
	root := tree(t, wpSite(sampleConfig))
	res := scanTree(t, root, Options{Select: engine.Selector{IDs: []string{"local-wp-s*"}}})
	if got := ids(res); !slices.Equal(got, []string{"local-wp-salts /wp-config.php"}) {
		t.Errorf("--id local-wp-s*: %v", got)
	}
	res = scanTree(t, root, Options{Select: engine.Selector{MinSeverity: engine.Medium, ExcludeIDs: []string{"local-wp-debug"}}})
	if got := ids(res); !slices.Equal(got, []string{"local-wp-salts /wp-config.php"}) {
		t.Errorf("--severity medium --exclude-id local-wp-debug: %v", got)
	}
}

func TestReadOnly(t *testing.T) {
	files := wpSite(sampleConfig)
	files[".env"] = "DB_PASSWORD=" + rawSecret
	files["backup.sql"] = "dump"
	root := tree(t, files)
	before := snapshot(t, root)
	scanTree(t, root, Options{})
	if after := snapshot(t, root); !slices.Equal(before, after) {
		t.Error("the scan changed the tree")
	}
}

func snapshot(t *testing.T, root string) []string {
	var out []string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		fi, _ := d.Info()
		line := p + " " + fi.Mode().String() + " " + fi.ModTime().String()
		if !d.IsDir() {
			b, _ := os.ReadFile(p)
			sum := sha256.Sum256(b)
			line += " " + string(sum[:])
		}
		out = append(out, line)
		return nil
	})
	return out
}

func TestRoot(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	os.WriteFile(file, nil, 0o600)
	if _, err := Root(filepath.Join(dir, "missing")); err == nil || !strings.Contains(err.Error(), "no such directory") {
		t.Errorf("missing: %v", err)
	}
	if _, err := Root(file); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("file: %v", err)
	}
	if got, err := Root(dir); err != nil || got != dir {
		t.Errorf("dir: %q %v", got, err)
	}
	home, _ := os.UserHomeDir()
	if got, err := Root("~"); err != nil || got != home {
		t.Errorf("~: %q %v", got, err)
	}
}

// A root that is a symlink, like a deploy's "current" link, scans the
// folder it points to: the walk does not stop at the link.
func TestLinkedRoot(t *testing.T) {
	root := tree(t, map[string]string{".env": "DB_PASSWORD=hunter2hunter2\n", "index.php": "<?php echo 1;"})
	link := filepath.Join(t.TempDir(), "current")
	if err := os.Symlink(root, link); err != nil {
		t.Skip("no symlinks:", err)
	}
	if got, err := Root(link); err != nil || got != root {
		t.Errorf("Root(link) = %q, %v; want %q", got, err, root)
	}
	direct, linked := scanTree(t, root, Options{}), scanTree(t, link, Options{})
	if find(linked, "local-dotenv") == nil {
		t.Errorf("linked root: no local-dotenv in %v", linked.Findings)
	}
	if len(direct.Findings) != len(linked.Findings) {
		t.Errorf("linked root found %d findings, the folder itself %d", len(linked.Findings), len(direct.Findings))
	}
}

func TestMaxEntries(t *testing.T) {
	root := tree(t, map[string]string{"a/b/c/d.txt": "", "e/f.txt": "", "g.txt": ""})
	res := scanTree(t, root, Options{MaxEntries: 2})
	if !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "stopped after 2 entries") }) {
		t.Errorf("warnings %v", res.Warnings)
	}
}

func TestCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var called atomic.Bool
	_, err := Scan(ctx, tree(t, wpSite(sampleConfig)), Options{Exec: noPHP, Advisor: advisorFunc(func() { called.Store(true) })}, engine.Hooks{})
	if !errors.Is(err, context.Canceled) || called.Load() {
		t.Errorf("err %v, advisor called %v", err, called.Load())
	}
}

type advisorFunc func()

func (a advisorFunc) Advise(context.Context, *url.URL, fingerprint.Result) ([]engine.Finding, []string) {
	a()
	return nil, nil
}

func TestExpandHome(t *testing.T) {
	home := func() (string, error) { return "/home/u", nil }
	for _, c := range []struct{ in, want string }{
		{"~", "/home/u"},
		{"~/site", "/home/u/site"},
		{`~\site`, "/home/u/site"},
		{`~\sites\blog`, "/home/u/sites/blog"},
		{"~user/site", "~user/site"}, // other users' homes aren't expanded
		{"/var/www", "/var/www"},
		{"site", "site"},
	} {
		got, err := expandHome(c.in, home)
		if err != nil || filepath.ToSlash(got) != c.want {
			t.Errorf("expandHome(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	if _, err := expandHome("~/x", func() (string, error) { return "", errors.New("no home") }); err == nil {
		t.Error("a missing home folder should be an error")
	}
}

func TestFileURL(t *testing.T) {
	for _, c := range []struct {
		in   string
		sep  byte
		want string
	}{
		{`C:\inetpub\wwwroot\.env`, '\\', "file:///C:/inetpub/wwwroot/.env"},
		{`d:\sites\my site\wp-config.php`, '\\', "file:///d:/sites/my%20site/wp-config.php"},
		{`\\fileserver\www\site\.env`, '\\', "file://fileserver/www/site/.env"},
		{"/var/www/html/.env", '/', "file:///var/www/html/.env"},
		{"/srv/a b/#x.php", '/', "file:///srv/a%20b/%23x.php"},
	} {
		if got := fileURLSep(c.in, c.sep).String(); got != c.want {
			t.Errorf("fileURLSep(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFindingURLsAreFileURLs(t *testing.T) {
	root := tree(t, map[string]string{".env": "DB_PASSWORD=" + rawSecret + "\n"})
	res := scanTree(t, root, Options{Exec: noPHP})
	if len(res.Findings) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range res.Findings {
		u, err := url.Parse(f.URL)
		if err != nil || u.Scheme != "file" || u.Host != "" || !strings.HasSuffix(u.Path, f.Path) {
			t.Errorf("%s: URL %q isn't a file URL of %s", f.ID, f.URL, f.Path)
		}
	}
}
