// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// DefaultDiscoverDepth is how many folders deep Discover looks when
// asked for depth 0. /var/www/example.com/htdocs/blog is 3 deep under
// /var/www; 6 leaves room for panel layouts such as
// /home/user/domains/example.com/public_html.
const DefaultDiscoverDepth = 6

// Install is a site found by Discover.
type Install struct {
	Path string // absolute folder to scan
	Kind string // "wordpress" or "laravel"
}

// Discovery is the result of Discover.
type Discovery struct {
	Root     string    // the absolute folder searched
	Installs []Install // sorted by path
	// Stopped is true when the search hit its entry cap, so installs
	// further down may be missing.
	Stopped bool
	// Unreadable counts folders that couldn't be listed.
	Unreadable int

	maxEntries int // the cap, for Warnings
}

// Warnings says why the search may have missed installs, if it may.
func (d Discovery) Warnings() []string {
	var w []string
	if d.Stopped {
		w = append(w, fmt.Sprintf("stopped looking after %s entries, so some installs under %s may be missing", thousands(d.maxEntries), d.Root))
	}
	if d.Unreadable > 0 {
		w = append(w, fmt.Sprintf("couldn't read %d %s under %s, so some installs may be missing", d.Unreadable, plural2(d.Unreadable, "folder", "folders"), d.Root))
	}
	return w
}

// Folders Discover never descends into: dependencies and version
// control hold copies of WordPress and Laravel that aren't sites.
var discoverSkip = map[string]bool{
	"vendor": true, "node_modules": true, "bower_components": true,
	".git": true, ".svn": true, ".hg": true,
}

// Inside an install, these hold the install's own code or uploads, not
// other sites. A WordPress copy inside wp-content (a backup plugin's
// staging folder, a theme's demo) isn't a separate site to scan.
var installSkip = map[string]map[string]bool{
	"wordpress": {"wp-admin": true, "wp-includes": true, "wp-content": true},
	"laravel":   {"storage": true, "bootstrap": true, "app": true, "config": true, "database": true, "resources": true, "routes": true, "tests": true},
}

// Discover finds every WordPress and Laravel install under root, root
// included, down to maxDepth folders (0 means DefaultDiscoverDepth). It
// doesn't follow links, so a link loop can't trap it. It stops
// after 250,000 entries. Other sites nested in an install (a WordPress
// in /blog) are found; copies inside dependency folders or wp-content
// are not.
func Discover(root string, maxDepth int) (Discovery, error) {
	return discover(root, maxDepth, defaultMaxEntries)
}

func discover(root string, maxDepth, maxEntries int) (Discovery, error) {
	abs, err := Root(root)
	if err != nil {
		return Discovery{}, err
	}
	if maxDepth <= 0 {
		maxDepth = DefaultDiscoverDepth
	}
	d := Discovery{Root: abs, maxEntries: maxEntries}
	seen := 0
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		kind := installKind(dir)
		if kind != "" {
			d.Installs = append(d.Installs, Install{Path: dir, Kind: kind})
		}
		if depth >= maxDepth || d.Stopped {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			d.Unreadable++
			return
		}
		for _, e := range entries {
			if seen++; seen > maxEntries {
				d.Stopped = true
				return
			}
			// Type bits come from the listing, so a link to a folder is
			// a link here, not a folder: it is never followed.
			name := e.Name()
			if !e.IsDir() || discoverSkip[name] || installSkip[kind][name] {
				continue
			}
			walk(filepath.Join(dir, name), depth+1)
		}
	}
	walk(abs, 0)
	slices.SortFunc(d.Installs, func(a, b Install) int { return strings.Compare(a.Path, b.Path) })
	return d, nil
}

// installKind says whether dir is the root of a WordPress or Laravel
// install, or "" when it is neither.
func installKind(dir string) string {
	if isFile(filepath.Join(dir, "wp-includes", "version.php")) &&
		(isFile(filepath.Join(dir, "wp-config.php")) || isFile(filepath.Join(dir, "wp-config-sample.php")) ||
			// WordPress also loads wp-config.php from the folder above,
			// when that folder isn't an install itself.
			isFile(filepath.Join(dir, "..", "wp-config.php")) && !isFile(filepath.Join(dir, "..", "wp-settings.php"))) {
		return "wordpress"
	}
	if isFile(filepath.Join(dir, "artisan")) && requiresLaravel(filepath.Join(dir, "composer.json")) {
		return "laravel"
	}
	return ""
}

// isFile reports whether path is a regular file or a link to one.
func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// requiresLaravel reports whether a composer.json requires
// laravel/framework, which tells an app from a package with an artisan
// script of its own.
func requiresLaravel(path string) bool {
	b, err := readHead(path, maxRead)
	if err != nil {
		return false
	}
	var c struct {
		Require map[string]json.RawMessage `json:"require"`
	}
	if json.Unmarshal(b, &c) != nil {
		return false
	}
	_, ok := c.Require["laravel/framework"]
	return ok
}

// String names the install for messages: "/var/www/blog (WordPress)".
func (i Install) String() string {
	switch i.Kind {
	case "wordpress":
		return i.Path + " (WordPress)"
	case "laravel":
		return i.Path + " (Laravel)"
	}
	return i.Path
}
