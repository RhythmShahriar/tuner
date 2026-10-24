// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"cmp"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// How long the php binary gets to print its version.
const phpTimeout = 5 * time.Second

// PHP_VERSION, e.g. 8.3.6 or, on Debian and Ubuntu builds, 8.1.2-1ubuntu2.14.
var phpVersionRe = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+)([^\s]*)`)

// phpVersion asks the php binary for its version. It returns the version,
// the full build string when it carries a distro suffix and a warning
// when the version couldn't be read.
//
// php runs with -n so no php.ini is loaded: an auto_prepend_file there
// could otherwise run site code.
func (s *scan) phpVersion(ctx context.Context) (version, build, warning string) {
	bin := cmp.Or(s.opts.PHP, "php")
	run := s.opts.Exec
	if run == nil {
		run = execOutput
	}
	ctx, cancel := context.WithTimeout(ctx, phpTimeout)
	defer cancel()
	out, err := run(ctx, bin, "-n", "-r", "echo PHP_VERSION;")
	switch {
	case errors.Is(err, exec.ErrNotFound) && s.opts.PHP == "":
		return "", "", "php not found on PATH, so the PHP version wasn't checked; pass --php /path/to/php"
	case err != nil:
		return "", "", "couldn't read the PHP version from " + bin + ": " + firstLine(err.Error())
	}
	m := phpVersionRe.FindStringSubmatch(strings.TrimSpace(string(out)))
	if m == nil {
		return "", "", "couldn't read the PHP version from " + bin + ": unexpected output " + quote(out)
	}
	if m[2] != "" {
		build = m[1] + m[2]
	}
	return m[1], build, ""
}

// phpSource says where the PHP version came from, for reports:
// "php on PATH", or "--php /usr/bin/php8.3" when the user chose the binary.
func (s *scan) phpSource() string {
	if s.opts.PHP == "" {
		return "php on PATH"
	}
	return "--php " + s.opts.PHP
}

// Files whose presence at the root marks a PHP project.
var phpMarkers = []string{"composer.json", "artisan", filepath.Join("wp-includes", "version.php")}

// isPHPProject reports whether root holds PHP code: a marker file, or a
// .php file at the root or one folder down. Dependency folders don't
// count: a JavaScript app can carry a stray .php file in node_modules.
func isPHPProject(root string) bool {
	for _, m := range phpMarkers {
		if fi, err := os.Stat(filepath.Join(root, m)); err == nil && fi.Mode().IsRegular() {
			return true
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	var dirs []string
	for _, e := range entries {
		name := e.Name()
		switch {
		case e.Type().IsRegular() && strings.HasSuffix(strings.ToLower(name), ".php"):
			return true
		case e.IsDir() && !strings.HasPrefix(name, ".") && name != "node_modules" && name != "vendor" && name != "bower_components":
			dirs = append(dirs, filepath.Join(root, name))
		}
	}
	for _, d := range dirs {
		sub, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range sub {
			if e.Type().IsRegular() && strings.HasSuffix(strings.ToLower(e.Name()), ".php") {
				return true
			}
		}
	}
	return false
}

func execOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // runs the php binary the user chose, with fixed arguments and no shell
	cmd.WaitDelay = time.Second
	return cmd.Output()
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

// quote renders untrusted command output for a message, short and on one line.
func quote(b []byte) string {
	s := firstLine(string(b))
	if r := []rune(s); len(r) > 60 {
		s = string(r[:60]) + "…"
	}
	return `"` + s + `"`
}
