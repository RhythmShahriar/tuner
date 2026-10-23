package local

import (
	"cmp"
	"context"
	"errors"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// How long the php binary gets to print its version.
const phpTimeout = 5 * time.Second

// PHP_VERSION, e.g. 8.3.6 or, on Debian and Ubuntu builds, 8.1.2-1ubuntu2.14.
var phpVersionRe = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+)([^\s]*)`)

// phpVersion asks the php binary for its version. It returns the version,
// the full build string when it carries a distro suffix, and a warning
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
