// Package local scans a site's files in place (white-box mode). Run on the
// server against the document root, it reads exact versions instead of
// guessing them from the outside: PHP from the php binary, WordPress core,
// plugins and themes from their own headers. It also reviews wp-config.php
// and flags files that don't belong in a web root.
//
// It only reads. It never changes the scanned files and never runs the
// site's code; the one command it runs asks the php binary for its version.
package local

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

// Files larger than this are only partly read.
const maxRead = 1 << 20

// Walks stop after this many entries, to bound scans of huge trees.
const defaultMaxEntries = 250_000

// Options configure a local scan.
type Options struct {
	// PHP is the php binary to ask for its version: a name on PATH or a
	// path. Empty means "php". The CLI's PHP may differ from the one the
	// web server runs, so point this at the right one when several exist.
	PHP string
	// Exec runs a command without a shell and returns its stdout. Tests
	// replace it; nil runs the real binary.
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
	// Advisor matches versions against vulnerability data, exactly as in
	// remote scans; wrap it in engine.Filtered to apply a selection.
	// Optional.
	Advisor engine.Advisor
	// OSV matches composer.lock packages against OSV.dev. Optional.
	OSV *OSV
	// Select filters local findings the way it filters advisor findings
	// (IDs, tags, minimum severity).
	Select engine.Selector
	// MaxEntries caps how many files and directories the walk visits; 0
	// means 250,000.
	MaxEntries int
	// ConfigRoot is where PHP's system configuration (/etc/php…, PHP-FPM
	// pools) is read from; empty means "/". Tests point it at a fake tree.
	ConfigRoot string
}

// Scan scans the directory root. The fingerprint and then each finding
// are reported through h.
func Scan(ctx context.Context, root string, opts Options, h engine.Hooks) (*engine.Result, error) {
	start := time.Now()
	abs, err := Root(root)
	if err != nil {
		return nil, err
	}
	s := &scan{opts: opts, root: abs, base: &url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}}
	if s.opts.MaxEntries <= 0 {
		s.opts.MaxEntries = defaultMaxEntries
	}
	res := &engine.Result{Target: abs}

	// Fingerprint: PHP from the machine, WordPress and Laravel from disk.
	fp := &res.Fingerprint
	add := func(t string) {
		if !fp.Has(t) {
			fp.Tech = append(fp.Tech, t)
		}
	}
	s.web = abs
	if s.wp = detectWordPress(abs); s.wp != nil {
		add("wordpress")
		add("php")
		fp.WordPress = s.wp.version
		fp.Components = s.wp.components
	}
	s.loadLock()
	if isLaravel(abs) {
		s.web = filepath.Join(abs, "public")
	}
	if s.web != abs || slices.ContainsFunc(s.pkgs, func(p Package) bool { return p.Name == "laravel/framework" }) {
		add("laravel")
		add("php")
	}
	if v, build, warn := s.phpVersion(ctx); v != "" {
		add("php")
		fp.PHP, fp.PHPBuild = v, build
	} else if warn != "" {
		s.warnings = append(s.warnings, warn)
	}
	if h.Fingerprint != nil {
		h.Fingerprint(*fp)
	}

	// Local checks, filtered by the selection, then version matching (the
	// caller filters the advisor, as remote scans do).
	var findings []engine.Finding
	if s.wp != nil {
		findings = append(findings, s.wpConfig()...)
		findings = append(findings, s.muPlugins()...)
	}
	findings = append(findings, s.laravelEnv()...)
	findings = append(findings, s.walk(ctx)...)
	findings = append(findings, s.composer(ctx)...)
	findings = append(findings, s.sessionUploadProgress(ctx)...)
	findings, _ = engine.Filtered(static(findings), opts.Select).Advise(ctx, s.base, *fp)
	if opts.Advisor != nil && ctx.Err() == nil {
		more, warnings := opts.Advisor.Advise(ctx, s.base, *fp)
		findings = append(findings, more...)
		s.warnings = append(s.warnings, warnings...)
	}

	for _, f := range findings {
		f.Target = res.Target
		res.Findings = append(res.Findings, f)
		if h.Finding != nil {
			h.Finding(f)
		}
	}
	sortFindings(res.Findings)
	res.Checks = s.checks
	res.Warnings = s.warnings
	res.Score = engine.Score(res.Findings)
	res.Duration = time.Since(start)
	return res, ctx.Err()
}

// Root resolves a local target to an absolute directory, expanding a
// leading ~. It errors if the target isn't a directory.
func Root(target string) (string, error) {
	p := target
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		p = filepath.Join(home, p[1:])
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(abs)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "", fmt.Errorf("%s: no such directory", target)
	case err != nil:
		return "", err
	case !fi.IsDir():
		return "", fmt.Errorf("%s: not a directory; point Tuner at the site's root folder", target)
	}
	return abs, nil
}

// scan is the state of one local scan.
type scan struct {
	opts     Options
	root     string   // absolute project root
	web      string   // document root: root, or root/public for Laravel
	base     *url.URL // file:// URL of root
	wp       *wordpress
	pkgs     []Package // from composer.lock
	checks   int       // local checks evaluated, for the summary
	warnings []string
}

func (s *scan) warn(format string, a ...any) {
	s.warnings = append(s.warnings, fmt.Sprintf(format, a...))
}

// finding builds a finding about the file at abs.
func (s *scan) finding(id string, sev engine.Severity, abs, title string, ev []string, impact, fix string, tags ...string) engine.Finding {
	u := *s.base
	u.Path = filepath.ToSlash(abs)
	return engine.Finding{
		ID:         id,
		Title:      title,
		Severity:   sev,
		Confidence: "high",
		URL:        u.String(),
		Path:       s.rel(abs),
		Evidence:   engine.Evidence{Request: "read " + s.rel(abs), Matched: ev},
		Impact:     impact,
		Fix:        fix,
		Tags:       append([]string{"local"}, tags...),
	}
}

// rel renders abs relative to the root as "/path", or as is when outside it.
func (s *scan) rel(abs string) string {
	r, err := filepath.Rel(s.root, abs)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(abs)
	}
	if r == "." {
		return "/"
	}
	return "/" + filepath.ToSlash(r)
}

// readHead reads at most n bytes of a file.
func readHead(path string, n int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // reading the user's own site files is the point of a local scan
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, n))
}

// static is an engine.Advisor that returns fixed findings, so local
// findings go through engine.Filtered like advisor ones.
type static []engine.Finding

func (st static) Advise(context.Context, *url.URL, fingerprint.Result) ([]engine.Finding, []string) {
	return st, nil
}

// sortFindings orders findings like remote scans: most severe first,
// confirmed before likely, then by ID and path.
func sortFindings(fs []engine.Finding) {
	slices.SortStableFunc(fs, func(a, b engine.Finding) int {
		if d := a.Severity.Rank() - b.Severity.Rank(); d != 0 {
			return d
		}
		if al, bl := a.Confidence == "low", b.Confidence == "low"; al != bl {
			if al {
				return 1
			}
			return -1
		}
		return strings.Compare(a.ID+a.Path, b.ID+b.Path)
	})
}
