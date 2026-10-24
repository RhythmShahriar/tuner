// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"crypto/md5" //nolint:gosec // WordPress core checksums are MD5
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
)

// pristine is a small WordPress 6.5.2 release: core files by path, and
// the akismet 5.3 plugin.
var (
	pristineCore = map[string]string{
		"index.php":                     "<?php define('WP_USE_THEMES', true); require __DIR__ . '/wp-blog-header.php';",
		"wp-login.php":                  "<?php // login",
		"wp-includes/version.php":       "<?php\n$wp_version = '6.5.2';\n",
		"wp-includes/load.php":          "<?php function wp_load() { return base64_decode('aGk='); }",
		"wp-admin/index.php":            "<?php // dashboard",
		"wp-content/index.php":          "<?php // Silence is golden.",
		"wp-content/themes/t/style.css": "/* bundled theme, updated separately */",
	}
	pristineAkismet = map[string]string{
		"akismet.php":       "<?php\n/*\nPlugin Name: Akismet\nVersion: 5.3\n*/\n",
		"class.akismet.php": "<?php class Akismet {}",
	}
)

func md5hex(s string) string    { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) } //nolint:gosec // see the import
func sha256hex(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// integrityTree is a WordPress install with the pristine files, then
// changes applied: "" deletes a file.
func integrityTree(t *testing.T, changes map[string]string) string {
	t.Helper()
	files := map[string]string{
		"wp-config.php": "<?php $table_prefix = 'x_';",
		// A plugin that isn't on wordpress.org.
		"wp-content/plugins/acme-custom/acme-custom.php": "<?php\n/*\nPlugin Name: Acme\nVersion: 1.0\n*/\n",
		"wp-content/plugins/acme-custom/extra.php":       "<?php // not checked",
		// Not core: never compared.
		"wp-content/uploads/a.txt": "upload",
	}
	for p, b := range pristineCore {
		files[p] = b
	}
	for p, b := range pristineAkismet {
		files["wp-content/plugins/akismet/"+p] = b
	}
	for p, b := range changes {
		if b == "" {
			delete(files, p)
		} else {
			files[p] = b
		}
	}
	return tree(t, files)
}

// fakeWPOrg answers like api.wordpress.org and downloads.wordpress.org,
// without the network.
type fakeWPOrg struct {
	mu       sync.Mutex
	requests []string
	coreJSON string // overrides the core answer when set
	down     bool
}

func (f *fakeWPOrg) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.requests = append(f.requests, r.URL.String())
	f.mu.Unlock()
	if f.down {
		return nil, errors.New("connection refused")
	}
	reply := func(status int, v any) (*http.Response, error) {
		var b []byte
		if s, ok := v.(string); ok {
			b = []byte(s)
		} else {
			b, _ = json.Marshal(v)
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(b))), Header: http.Header{}, Request: r}, nil
	}
	switch {
	case r.URL.Host == "core.test" && r.URL.Path == "/core/checksums/1.0/":
		if f.coreJSON != "" {
			return reply(200, f.coreJSON)
		}
		if r.URL.Query().Get("version") != "6.5.2" {
			return reply(200, `{"checksums":false}`)
		}
		sums := map[string]string{}
		for p, b := range pristineCore {
			sums[p] = md5hex(b)
		}
		return reply(200, map[string]any{"checksums": sums})
	case r.URL.Host == "dl.test" && r.URL.Path == "/plugin-checksums/akismet/5.3.json":
		files := map[string]any{}
		for p, b := range pristineAkismet {
			files[p] = map[string]any{"md5": md5hex(b), "sha256": sha256hex(b)}
		}
		// Rebuilt releases list several hashes.
		files["class.akismet.php"] = map[string]any{"sha256": []string{"00", sha256hex(pristineAkismet["class.akismet.php"])}}
		return reply(200, map[string]any{"plugin": "akismet", "version": "5.3", "files": files})
	}
	return reply(404, `{"error":"not found"}`)
}

func (f *fakeWPOrg) client(cache string, offline bool) *Checksums {
	return &Checksums{HTTP: &http.Client{Transport: f}, CoreBase: "https://core.test", PluginBase: "https://dl.test", CacheDir: cache, Offline: offline}
}

func integrityScan(t *testing.T, root string, c *Checksums) *engine.Result {
	t.Helper()
	return scanTree(t, root, Options{Exec: noPHP, Integrity: true, Checksums: c})
}

// integrityFindings are the integrity findings about files, without the
// info note about plugins that couldn't be compared.
func integrityFindings(res *engine.Result) []engine.Finding {
	var out []engine.Finding
	for _, f := range res.Findings {
		if strings.HasPrefix(f.ID, "local-integrity-") && f.ID != "local-integrity-plugin-unchecked" {
			out = append(out, f)
		}
	}
	return out
}

func TestIntegrityPristine(t *testing.T) {
	api := &fakeWPOrg{}
	res := integrityScan(t, integrityTree(t, nil), api.client("", false))
	if got := integrityFindings(res); len(got) != 0 {
		t.Errorf("pristine tree: %v", ids(&engine.Result{Findings: got}))
	}
	// The plugin that can't be compared gets an info note, not a
	// warning: the scan isn't degraded.
	note := find(res, "local-integrity-plugin-unchecked")
	if note == nil || note.Severity != engine.Info || note.Title != "1 plugin not on wordpress.org wasn't compared" ||
		!slices.Equal(note.Evidence.Matched, []string{"no checksums to compare: acme-custom"}) || note.Path != "/wp-content/plugins" {
		t.Errorf("note %+v", note)
	}
	if hasWarning(res, "integrity:") {
		t.Errorf("warnings %q", res.Warnings)
	}
	if res.Checks < len(integrityChecks) {
		t.Errorf("checks %d", res.Checks)
	}
}

func TestIntegrityFindsChanges(t *testing.T) {
	const secret = "DB_PASSWORD=" + rawSecret
	api := &fakeWPOrg{}
	root := integrityTree(t, map[string]string{
		"wp-includes/load.php":                         "<?php eval($_POST['x']); // " + secret,
		"wp-includes/x.php":                            "<?php // dropped by an attacker",
		"wp-includes/js/x.js":                          "not php: not reported",
		"wp-login.php":                                 "",
		"wp-content/plugins/akismet/class.akismet.php": "<?php class Akismet { /* edited */ }",
		"wp-content/plugins/akismet/shell.php":         "<?php // backdoor",
		"wp-content/plugins/akismet/readme.txt":        "not php: not reported",
		"wp-content/index.php":                         "<?php // edited: wp-content isn't compared",
	})
	res := integrityScan(t, root, api.client("", false))
	got := map[string]engine.Finding{}
	for _, f := range integrityFindings(res) {
		got[f.ID+" "+f.Path] = f
	}
	want := map[string]engine.Severity{
		"local-integrity-core-modified /wp-includes/load.php":                           engine.Critical,
		"local-integrity-core-unknown /wp-includes/x.php":                               engine.High,
		"local-integrity-core-missing /":                                                engine.Low,
		"local-integrity-plugin-modified /wp-content/plugins/akismet/class.akismet.php": engine.High,
		"local-integrity-plugin-unknown /wp-content/plugins/akismet/shell.php":          engine.Medium,
	}
	for k, sev := range want {
		if f, ok := got[k]; !ok || f.Severity != sev {
			t.Errorf("%s: got %+v", k, f)
		}
	}
	if len(got) != len(want) {
		t.Errorf("findings %v", slices.Sorted(maps.Keys(got)))
	}
	mod := got["local-integrity-core-modified /wp-includes/load.php"]
	ev := strings.Join(mod.Evidence.Matched, "\n")
	if !strings.Contains(ev, "expected "+md5hex(pristineCore["wp-includes/load.php"])+" for WordPress 6.5.2 (en_US)") {
		t.Errorf("evidence %q", ev)
	}
	for _, f := range res.Findings {
		b, _ := json.Marshal(f)
		if strings.Contains(string(b), rawSecret) || strings.Contains(string(b), "eval(") {
			t.Errorf("%s shows file contents: %s", f.ID, b)
		}
	}
	missing := got["local-integrity-core-missing /"]
	if missing.Title != "1 WordPress core file missing" || !slices.Equal(missing.Evidence.Matched, []string{"/wp-login.php"}) {
		t.Errorf("missing: %q %q", missing.Title, missing.Evidence.Matched)
	}
}

func TestIntegrityHashesWholeFile(t *testing.T) {
	// Core's big bundled scripts are over the 1 MiB read cap: a change
	// past it must still count.
	big := strings.Repeat("a", maxRead+10)
	pristineCore["wp-includes/js/big.js"] = big
	t.Cleanup(func() { delete(pristineCore, "wp-includes/js/big.js") })
	api := &fakeWPOrg{}
	res := integrityScan(t, integrityTree(t, map[string]string{"wp-includes/js/big.js": big[:maxRead+5] + "bbbbb"}), api.client("", false))
	if f := find(res, "local-integrity-core-modified"); f == nil || f.Path != "/wp-includes/js/big.js" {
		t.Errorf("findings %v", ids(res))
	}
	res = integrityScan(t, integrityTree(t, nil), api.client("", false))
	if len(integrityFindings(res)) != 0 {
		t.Errorf("pristine big file: %v", ids(res))
	}
}

func TestIntegrityOffline(t *testing.T) {
	cache := t.TempDir()
	changed := map[string]string{"wp-includes/load.php": "<?php // changed"}

	// Offline with nothing cached: a warning, no findings, no requests.
	api := &fakeWPOrg{}
	res := integrityScan(t, integrityTree(t, changed), api.client(cache, true))
	if len(integrityFindings(res)) != 0 || len(api.requests) != 0 {
		t.Errorf("offline without cache: %v, requests %v", ids(res), api.requests)
	}
	if !hasWarning(res, "integrity: no cached checksums for WordPress 6.5.2 (en_US) while offline; run once online to cache them") ||
		!hasWarning(res, "integrity: skipped 2 plugins with no cached checksums while offline: acme-custom, akismet") {
		t.Errorf("warnings %q", res.Warnings)
	}

	// Online once fills the cache.
	integrityScan(t, integrityTree(t, nil), api.client(cache, false))

	// Offline with the cache: the same answers without the network,
	// including that acme-custom isn't on wordpress.org.
	down := &fakeWPOrg{down: true}
	res = integrityScan(t, integrityTree(t, changed), down.client(cache, true))
	if f := find(res, "local-integrity-core-modified"); f == nil || len(down.requests) != 0 {
		t.Errorf("offline with cache: %v, requests %v", ids(res), down.requests)
	}
	if f := find(res, "local-integrity-plugin-unchecked"); f == nil || f.Evidence.Matched[0] != "no checksums to compare: acme-custom" {
		t.Errorf("findings %v", ids(res))
	}

	// Online but down, with the cache: the cache still answers.
	res = integrityScan(t, integrityTree(t, changed), down.client(cache, false))
	if find(res, "local-integrity-core-modified") == nil {
		t.Errorf("down with cache: %v %q", ids(res), res.Warnings)
	}
}

func TestIntegrityServiceDown(t *testing.T) {
	down := &fakeWPOrg{down: true}
	res := integrityScan(t, integrityTree(t, nil), down.client("", false))
	if len(integrityFindings(res)) != 0 {
		t.Errorf("findings %v", ids(res))
	}
	if !hasWarning(res, "integrity: couldn't get checksums for WordPress 6.5.2 (en_US): ") ||
		!hasWarning(res, "integrity: couldn't get checksums for 2 plugins: acme-custom: ") {
		t.Errorf("warnings %q", res.Warnings)
	}
}

func TestIntegrityLocaleAndShapes(t *testing.T) {
	// A localized package asks for its locale.
	api := &fakeWPOrg{}
	root := integrityTree(t, map[string]string{"wp-includes/version.php": "<?php\n$wp_version = '6.5.2';\n$wp_local_package = 'de_DE';\n"})
	integrityScan(t, root, api.client("", false))
	if !slices.ContainsFunc(api.requests, func(u string) bool {
		return strings.Contains(u, "locale=de_DE") && strings.Contains(u, "version=6.5.2")
	}) {
		t.Errorf("requests %v", api.requests)
	}

	// The answer keyed by version, as the API sends without a locale.
	sums := map[string]string{}
	for p, b := range pristineCore {
		sums[p] = md5hex(b)
	}
	sums["wp-admin/index.php"] = md5hex("something else")
	b, _ := json.Marshal(map[string]any{"checksums": map[string]any{"6.5.2": sums}})
	api = &fakeWPOrg{coreJSON: string(b)}
	res := integrityScan(t, integrityTree(t, nil), api.client("", false))
	if f := find(res, "local-integrity-core-modified"); f == nil || f.Path != "/wp-admin/index.php" {
		t.Errorf("by-version answer: %v", ids(res))
	}

	// An unknown release.
	api = &fakeWPOrg{coreJSON: `{"checksums":false}`}
	res = integrityScan(t, integrityTree(t, nil), api.client("", false))
	if !hasWarning(res, "integrity: WordPress.org has no checksums for WordPress 6.5.2 (en_US), so core files weren't compared") {
		t.Errorf("warnings %q", res.Warnings)
	}
}

func TestIntegrityOff(t *testing.T) {
	api := &fakeWPOrg{}
	res := scanTree(t, integrityTree(t, map[string]string{"wp-includes/x.php": "<?php"}), Options{Exec: noPHP, Checksums: api.client("", false)})
	if len(integrityFindings(res)) != 0 || len(api.requests) != 0 {
		t.Errorf("integrity ran without being asked: %v %v", ids(res), api.requests)
	}
	// Not WordPress: says so.
	res = scanTree(t, tree(t, map[string]string{"index.php": "<?php"}), Options{Exec: noPHP, Integrity: true, Checksums: api.client("", false)})
	if !hasWarning(res, "integrity: no WordPress install found, so no files were compared with checksums") || len(api.requests) != 0 {
		t.Errorf("warnings %q, requests %v", res.Warnings, api.requests)
	}
}

func TestChecksumsCacheKey(t *testing.T) {
	c := &Checksums{CacheDir: "/cache"}
	if p := c.path("plugin", "../../etc@1"); path.Dir(p) != "/cache/plugin" {
		t.Errorf("cache path %q escapes the cache", p)
	}
}

func TestIntegrityLinks(t *testing.T) {
	// Core and plugin files replaced by links: a link to a file inside
	// the install is compared like the file, a link outside it is
	// reported because its target can't be compared.
	outside := tree(t, map[string]string{"evil.php": "<?php eval($_POST['x']);"})
	root := integrityTree(t, map[string]string{
		"shared/admin-index.php": pristineCore["wp-admin/index.php"],
		"shared/login.php":       "<?php // changed login",
	})
	links := map[string]string{
		"wp-includes/load.php": filepath.Join(outside, "evil.php"),
		"wp-admin/index.php":   filepath.Join("..", "shared", "admin-index.php"),
		"wp-login.php":         filepath.Join("shared", "login.php"),
		"wp-content/plugins/akismet/class.akismet.php": filepath.Join(outside, "evil.php"),
	}
	for p, target := range links {
		link := filepath.Join(root, filepath.FromSlash(p))
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Skip("no links:", err)
		}
	}
	api := &fakeWPOrg{}
	res := integrityScan(t, root, api.client("", false))
	got := map[string]engine.Finding{}
	for _, f := range integrityFindings(res) {
		got[f.ID+" "+f.Path] = f
	}
	want := map[string]string{
		"local-integrity-core-modified /wp-includes/load.php":                           "WordPress core file replaced by a link",
		"local-integrity-core-modified /wp-login.php":                                   "Modified WordPress core file",
		"local-integrity-plugin-modified /wp-content/plugins/akismet/class.akismet.php": "File in plugin akismet replaced by a link",
	}
	for k, title := range want {
		if f, ok := got[k]; !ok || f.Title != title {
			t.Errorf("%s: got %+v", k, f)
		}
	}
	if len(got) != len(want) {
		t.Errorf("findings %v", slices.Sorted(maps.Keys(got)))
	}
	ev := strings.Join(got["local-integrity-core-modified /wp-includes/load.php"].Evidence.Matched, "\n")
	if !strings.Contains(ev, "a link to "+filepath.Join(outside, "evil.php")+" outside the install, so it wasn't compared") {
		t.Errorf("evidence %q", ev)
	}
	if f := got["local-integrity-core-modified /wp-includes/load.php"]; f.Severity != engine.High {
		t.Errorf("severity %s", f.Severity)
	}
}
