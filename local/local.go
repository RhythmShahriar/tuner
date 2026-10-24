// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

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
	"hash"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

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
	// PHPExplicit is true when the user chose the binary (--php). php is
	// then asked even when the folder doesn't look like a PHP project. A
	// non-empty PHP counts as explicit too.
	PHPExplicit bool
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

	// Integrity compares WordPress core and wordpress.org plugin files
	// with their published checksums. It fetches them, unless Checksums
	// is offline.
	Integrity bool
	// Checksums fetches the checksums for Integrity; nil uses a default
	// client without a disk cache.
	Checksums *Checksums

	// SkipDirs are folders under the root the walk leaves out: nested
	// installs that --discover scans on their own, so their findings
	// aren't reported twice. Absolute, or relative to the root.
	SkipDirs []string

	// Rules holds local rule files (*.yaml at its root, see Rule) to use
	// instead of the built-in ones, such as a check pack's newer copies.
	// nil uses the rules built into Tuner.
	Rules fs.FS

	// read replaces readFile in the walk and in the reads before it, so
	// tests can count opens.
	read func(path string, n int64, hs ...hash.Hash) ([]byte, int64, error)
}

// Scan scans the directory root. The fingerprint and then each finding
// are reported through h.
func Scan(ctx context.Context, root string, opts Options, h engine.Hooks) (*engine.Result, error) {
	res, _, err := scanStatus(ctx, root, opts, h)
	return res, err
}

// scanStatus is Scan, also saying how complete the scan was. engine.Result
// can't carry that yet; once it gains Complete, StoppedBy and VulnData,
// Scan copies the status into them.
func scanStatus(ctx context.Context, root string, opts Options, h engine.Hooks) (*engine.Result, status, error) {
	start := time.Now()
	abs, err := Root(root)
	if err != nil {
		return nil, status{}, err
	}
	s := &scan{opts: opts, root: abs, base: fileURL(abs)}
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
	if s.wp = s.detectWordPress(ctx, abs); s.wp != nil {
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
	// The php binary describes this machine, not the folder: only ask it
	// when the folder is PHP code, or a Next.js app would get the
	// laptop's PHP vulnerabilities.
	if s.opts.PHPExplicit || s.opts.PHP != "" || fp.Has("php") || isPHPProject(abs) {
		if v, build, warn := s.phpVersion(ctx); v != "" {
			add("php")
			fp.PHP, fp.PHPBuild, fp.PHPSource = v, build, s.phpSource()
		} else if warn != "" {
			s.warnings = append(s.warnings, warn)
		}
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
	stray, session, rules := &strayVisitor{s: s}, &sessionVisitor{s: s}, &rulesVisitor{s: s}
	for _, r := range s.rules() {
		if r.Scope == scopeWeb {
			stray.rules = append(stray.rules, r)
		} else {
			rules.rules = append(rules.rules, r)
		}
	}
	visitors := []visitor{stray, session, rules}
	integrity, info := s.prepareIntegrity(ctx)
	findings = append(findings, info...)
	if integrity != nil {
		visitors = append(visitors, integrity)
	}
	s.walkTree(ctx, visitors...)
	findings = append(findings, stray.findings()...)
	findings = append(findings, rules.findings()...)
	if integrity != nil {
		findings = append(findings, integrity.done()...)
	}
	osv := s.vulnStep(func() { findings = append(findings, s.composer(ctx)...) })
	findings = append(findings, s.sessionUploadProgress(ctx, session)...)
	findings, _ = engine.Filtered(static(findings), opts.Select).Advise(ctx, s.base, *fp)
	advisor := s.advise(ctx, *fp, &findings)

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
	st := status{complete: s.stoppedBy == "", stoppedBy: s.stoppedBy, vulnData: combineVulnData(advisor, osv)}
	if observe != nil {
		observe(opts, res)
	}
	return res, st, ctx.Err()
}

// observe, when set, sees every scan's result. Tests use it to check
// that each finding ID the suite produces is in the Catalog.
var observe func(Options, *engine.Result)

// Root resolves a local target to an absolute directory, expanding a
// leading ~, ~/ or ~\ to the home folder on every OS. It errors if the
// target isn't a directory.
func Root(target string) (string, error) {
	p, err := expandHome(target, os.UserHomeDir)
	if err != nil {
		return "", err
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

// expandHome replaces a leading ~ with the home folder. Both separators
// count after it: Windows users type ~\site; a script written there
// may still be run on Linux or macOS.
func expandHome(p string, home func() (string, error)) (string, error) {
	if p != "~" && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, `~\`) {
		return p, nil
	}
	h, err := home()
	if err != nil {
		return "", err
	}
	rest := p[1:]
	if strings.HasPrefix(rest, `\`) {
		rest = strings.ReplaceAll(rest, `\`, "/") // Windows style throughout
	}
	return filepath.Join(h, filepath.FromSlash(rest)), nil
}

// fileURL is the file:// URL of an absolute local path.
func fileURL(abs string) *url.URL { return fileURLSep(abs, filepath.Separator) }

// fileURLSep builds the file URL of a path that uses sep, so tests can
// cover Windows paths on any OS. A drive letter gets a leading slash
// (file:///C:/inetpub/wwwroot/.env, not file://C:/… with C: as the host),
// and a UNC path \\server\share\x becomes file://server/share/x.
func fileURLSep(abs string, sep byte) *url.URL {
	p := abs
	if sep != '/' {
		p = strings.ReplaceAll(p, string(sep), "/")
	}
	u := &url.URL{Scheme: "file"}
	switch {
	case strings.HasPrefix(p, "//"):
		host, rest, _ := strings.Cut(p[2:], "/")
		u.Host, u.Path = host, "/"+rest
	case len(p) >= 2 && p[1] == ':' && (p[0]|0x20 >= 'a' && p[0]|0x20 <= 'z'):
		u.Path = "/" + p
	default:
		u.Path = p
	}
	return u
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
	skipped  map[string]bool // special files already warned about
	// stoppedBy is "budget" once the walk stopped at MaxEntries.
	stoppedBy string
	// mu guards warnings and skipped: the walk's workers warn too.
	mu sync.Mutex
}

func (s *scan) warn(format string, a ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.warnings = append(s.warnings, fmt.Sprintf(format, a...))
}

// finding builds a finding about the file at abs.
//
// File and folder names come from the site tree. Anyone who can
// upload a file picks its name, so every text field is cleaned with
// cleanText: a name with escape sequences or bidi overrides would
// otherwise change colors in the report or reorder its lines, in a
// terminal or in Markdown.
func (s *scan) finding(id string, sev engine.Severity, abs, title string, ev []string, impact, fix string, tags ...string) engine.Finding {
	rel := cleanText(s.rel(abs), false)
	matched := make([]string, len(ev))
	for i, line := range ev {
		matched[i] = cleanText(line, false)
	}
	return engine.Finding{
		ID:         id,
		Title:      cleanText(title, false),
		Severity:   sev,
		Confidence: confidenceHigh,
		URL:        fileURL(abs).String(),
		Path:       rel,
		Evidence:   engine.Evidence{Request: "read " + rel, Matched: matched},
		Impact:     cleanText(impact, true),
		Fix:        cleanText(fix, true),
		Tags:       append([]string{"local"}, tags...),
	}
}

// cleanText makes s safe to print: invalid UTF-8 becomes "?" and control
// and format characters become ".". Format characters include the bidi
// overrides that would reorder how a crafted name shows. multiline keeps
// line breaks and tabs, for the authored impact and fix texts.
func cleanText(s string, multiline bool) string {
	s = strings.ToValidUTF8(s, "?")
	return strings.Map(func(r rune) rune {
		if multiline && (r == '\n' || r == '\t') {
			return r
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '.'
		}
		return r
	}, s)
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

// notRegularError is returned for a path that isn't a regular file (or a
// link to one): a FIFO, socket or device. Reading those can block forever
// or never end, so local scans skip them.
type notRegularError struct {
	path string
	kind string // "a named pipe", "a link to a device", …
}

func (e *notRegularError) Error() string { return e.path + " is " + e.kind + ", not a regular file" }

// readHead reads at most n bytes of a regular file. Anything else is
// refused with a *notRegularError before it is opened and again after
// it, in case the path was swapped in between.
func readHead(path string, n int64) ([]byte, error) {
	b, _, err := readFile(path, n)
	return b, err
}

// readFile is readHead that also returns the file's size and feeds the
// whole file, not just its head, to hs. The file is opened once.
func readFile(path string, n int64, hs ...hash.Hash) ([]byte, int64, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, -1, err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		// Links to regular files are fine; WordPress setups often link
		// wp-config.php from elsewhere.
		target, err := os.Stat(path)
		if err != nil {
			return nil, -1, err
		}
		if !target.Mode().IsRegular() {
			return nil, -1, &notRegularError{path, "a link to " + fileKind(target.Mode())}
		}
	} else if !fi.Mode().IsRegular() {
		return nil, -1, &notRegularError{path, fileKind(fi.Mode())}
	}
	f, err := openRead(path)
	if err != nil {
		return nil, -1, err
	}
	defer func() { _ = f.Close() }()
	if fi, err = f.Stat(); err != nil {
		return nil, -1, err
	} else if !fi.Mode().IsRegular() {
		return nil, -1, &notRegularError{path, fileKind(fi.Mode())}
	}
	head, err := io.ReadAll(io.LimitReader(f, n))
	if err != nil || len(hs) == 0 {
		return head, fi.Size(), err
	}
	w := make([]io.Writer, len(hs))
	for i, h := range hs {
		w[i] = h
	}
	all := io.MultiWriter(w...)
	_, _ = all.Write(head) // hash.Hash writes never fail
	_, err = io.Copy(all, f)
	return head, fi.Size(), err
}

// readHead is readHead that warns when it skips a FIFO, socket or device,
// so a scan that left a file out says so. It goes through Options.read
// like the walk, so tests count every open.
func (s *scan) readHead(path string, n int64) ([]byte, error) {
	read := s.opts.read
	if read == nil {
		read = readFile
	}
	b, _, err := read(path, n)
	if nr := (*notRegularError)(nil); errors.As(err, &nr) {
		s.skip(path, nr.kind)
	}
	return b, err
}

// skip warns once per path that a special file was left out.
func (s *scan) skip(path, kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.skipped == nil {
		s.skipped = map[string]bool{}
	}
	if !s.skipped[path] {
		s.skipped[path] = true
		s.warnings = append(s.warnings, fmt.Sprintf("skipped %s: it is %s, not a regular file", s.rel(path), kind))
	}
}

func isNotRegular(err error) bool {
	var nr *notRegularError
	return errors.As(err, &nr)
}

// fileKind names a non-regular file type for messages.
func fileKind(m fs.FileMode) string {
	switch {
	case m.IsDir():
		return "a folder"
	case m&fs.ModeNamedPipe != 0:
		return "a named pipe"
	case m&fs.ModeSocket != 0:
		return "a socket"
	case m&fs.ModeCharDevice != 0:
		return "a character device"
	case m&fs.ModeDevice != 0:
		return "a device"
	}
	return "a special file"
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
		if al, bl := a.Confidence == confidenceLow, b.Confidence == confidenceLow; al != bl {
			if al {
				return 1
			}
			return -1
		}
		return strings.Compare(a.ID+a.Path, b.ID+b.Path)
	})
}
