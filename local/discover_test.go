// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// discoverTree is a host with three WordPress sites (one in /blog of
// another), a Laravel app and copies that aren't sites.
func discoverTree(t *testing.T) string {
	wp := func(dir string) map[string]string {
		return map[string]string{
			dir + "/wp-includes/version.php": "<?php $wp_version = '6.5.2';",
			dir + "/wp-config.php":           "<?php",
		}
	}
	files := map[string]string{
		// A Laravel app, and a package in its vendor with an artisan of
		// its own that must not count.
		"app.example/artisan":                                   "#!/usr/bin/env php",
		"app.example/composer.json":                             `{"require": {"php": "^8.2", "laravel/framework": "^11.0"}}`,
		"app.example/vendor/acme/tool/artisan":                  "",
		"app.example/vendor/acme/tool/composer.json":            `{"require": {"laravel/framework": "^11.0"}}`,
		"tool/artisan":                                          "",
		"tool/composer.json":                                    `{"require": {"symfony/console": "^7"}}`,
		"shop/wp-config-sample.php":                             "<?php",
		"shop/wp-includes/version.php":                          "<?php $wp_version = '6.4';",
		"shop/wp-content/plugins/x/wp-includes/version.php":     "",
		"shop/wp-content/plugins/x/wp-config.php":               "",
		"app.example/vendor/johnpbloch/wp-includes/version.php": "",
		"app.example/vendor/johnpbloch/wp-config.php":           "",
		"node_modules/wp/wp-includes/version.php":               "",
		"node_modules/wp/wp-config-sample.php":                  "",
		// wp-includes without a config: not an install.
		"half/wp-includes/version.php": "",
	}
	for _, dir := range []string{"example.com/htdocs", "example.com/htdocs/blog"} {
		for k, v := range wp(dir) {
			files[k] = v
		}
	}
	root := tree(t, files)
	// A link loop: following it would never end.
	if err := os.Symlink(root, filepath.Join(root, "example.com", "loop")); err != nil {
		t.Skip("no symlinks:", err)
	}
	return root
}

func TestDiscover(t *testing.T) {
	root := discoverTree(t)
	d, err := Discover(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, in := range d.Installs {
		r, _ := filepath.Rel(root, in.Path)
		got = append(got, filepath.ToSlash(r)+" "+in.Kind)
	}
	want := []string{
		"app.example laravel",
		"example.com/htdocs wordpress",
		"example.com/htdocs/blog wordpress",
		"shop wordpress",
	}
	if !slices.Equal(got, want) {
		t.Errorf("installs\n got %q\nwant %q", got, want)
	}
	if d.Stopped || d.Root != root {
		t.Errorf("discovery %+v", d)
	}
	if s := d.Installs[1].String(); s != filepath.Join(root, "example.com", "htdocs")+" (WordPress)" {
		t.Errorf("String() = %q", s)
	}
}

func TestDiscoverRootIsInstall(t *testing.T) {
	root := tree(t, map[string]string{
		"wp-includes/version.php": "",
		"wp-config.php":           "",
	})
	d, err := Discover(root, 0)
	if err != nil || len(d.Installs) != 1 || d.Installs[0].Path != root {
		t.Fatalf("Discover = %+v, %v", d, err)
	}
}

func TestDiscoverConfigAbove(t *testing.T) {
	// wp-config.php one folder up, as WordPress allows.
	root := tree(t, map[string]string{
		"site/wp-config.php":                  "",
		"site/public/wp-includes/version.php": "",
		"site/public/wp-settings.php":         "",
	})
	d, _ := Discover(root, 0)
	if len(d.Installs) != 1 || d.Installs[0].Path != filepath.Join(root, "site", "public") {
		t.Fatalf("installs %+v", d.Installs)
	}
}

func TestDiscoverDepthAndCap(t *testing.T) {
	root := discoverTree(t)
	// Depth 1 reaches app.example and shop but not example.com/htdocs.
	d, _ := Discover(root, 1)
	if len(d.Installs) != 2 {
		t.Errorf("depth 1: %+v", d.Installs)
	}
	d, _ = discover(root, 0, 3)
	if !d.Stopped {
		t.Error("cap of 3 entries didn't stop the search")
	}
	if w := d.Warnings(); len(w) != 1 || w[0] != "stopped looking after 3 entries, so some installs under "+root+" may be missing" {
		t.Errorf("warnings %q", w)
	}
}

func TestDiscoverNone(t *testing.T) {
	d, err := Discover(tree(t, map[string]string{"index.html": ""}), 0)
	if err != nil || len(d.Installs) != 0 {
		t.Fatalf("Discover = %+v, %v", d, err)
	}
	if _, err := Discover(filepath.Join(t.TempDir(), "missing"), 0); err == nil {
		t.Error("missing folder: no error")
	}
}

func TestDiscoverUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every folder")
	}
	root := tree(t, map[string]string{"locked/x/": ""})
	locked := filepath.Join(root, "locked")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	d, _ := Discover(root, 0)
	if w := d.Warnings(); len(w) != 1 || w[0] != "couldn't read 1 folder under "+root+", so some installs may be missing" {
		t.Errorf("warnings %q", w)
	}
}
