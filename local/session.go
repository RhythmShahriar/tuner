// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
)

// CVE-2026-115560 is an unpatched flaw in PHP's session upload progress.
// It is only reachable when all four hold:
//
//  1. session.serialize_handler is php_binary or php_serialize,
//  2. the application switches it to php at runtime with ini_set(),
//  3. before calling session_start(), and
//  4. session.upload_progress.enabled is on (the default).
//
// Conditions 1 and 4 are configuration, read from what PHP reports and
// from the web server SAPIs' ini files and FPM pools, plus .user.ini and
// .htaccess overrides in the site. 2 and 3 are code, found by reading the
// site's PHP files. Nothing is run except php asking for its own settings.
const sessionCheckID = "local-php-session-upload-progress"

const sessionCVE = "CVE-2026-115560"

// Unsafe base handlers for condition 1.
var unsafeHandlers = []string{"php_binary", "php_serialize"}

var (
	iniSetHandler = regexp.MustCompile(`(?i)\bini_(?:set|alter)\s*\(\s*(['"])session\.serialize_handler['"]\s*,\s*([^;]*?)\)\s*;`)
	sessionStart  = regexp.MustCompile(`(?i)\bsession_start\s*\(`)
	literalArg    = regexp.MustCompile(`^\s*['"]([A-Za-z_]+)['"]\s*$`)
	iniLine       = regexp.MustCompile(`^\s*([A-Za-z0-9_.]+)\s*=\s*(.*?)\s*$`)
	poolLine      = regexp.MustCompile(`^\s*php(?:_admin)?_(?:value|flag)\[\s*([^\]]+?)\s*\]\s*=\s*(.*?)\s*$`)
	htaccessLine  = regexp.MustCompile(`(?i)^\s*php_(?:admin_)?(?:value|flag)\s+(\S+)\s+(.*?)\s*$`)
	debianCLIIni  = regexp.MustCompile(`^(.*/php/[0-9.]+)/cli/php\.ini$`)
)

// sessionCtx is one place PHP runs with its own settings: the CLI, a
// web server SAPI, an FPM pool, or a directory with overrides.
type sessionCtx struct {
	name                    string
	handler, handlerSrc     string
	progress                bool
	progressSrc             string
	progressSet, handlerSet bool // explicitly configured, not the default
	web                     bool // a web server's own settings (SAPI or pool), not the CLI's
}

// handlerSwitch is an ini_set() of session.serialize_handler in site code.
type handlerSwitch struct {
	file          string // absolute
	line          int
	value         string // the literal value, or "" for an expression
	startLine     int    // first session_start() after it in the same file, 0 if none
	startedBefore bool   // session_start() only appears before it in the file
}

// sessionUploadProgress checks the CVE-2026-115560 preconditions.
func (s *scan) sessionUploadProgress(ctx context.Context) []engine.Finding {
	s.checks++
	switches, overrides := s.sessionCode(ctx)
	var toPHP, toUnsafe []handlerSwitch
	for _, sw := range switches {
		switch {
		case sw.value == "" || strings.EqualFold(sw.value, "php"):
			toPHP = append(toPHP, sw)
		case slices.Contains(unsafeHandlers, strings.ToLower(sw.value)):
			toUnsafe = append(toUnsafe, sw)
		}
	}
	// PHP: apps that never switch the handler at runtime aren't affected.
	if len(toPHP) == 0 {
		return nil
	}

	ctxs := applyOverrides(s.sessionConfig(ctx), overrides, s.web)
	// Upload progress only exists for web requests, so once a web server's
	// own settings are known the CLI's don't count. Without them (e.g. the
	// official Docker images, where both share one config) the CLI stands in.
	if slices.ContainsFunc(ctxs, func(c sessionCtx) bool { return c.web }) {
		ctxs = slices.DeleteFunc(ctxs, func(c sessionCtx) bool { return !c.web })
	}

	var unsafe, progressOn, progressOff []sessionCtx
	for _, c := range ctxs {
		if slices.Contains(unsafeHandlers, strings.ToLower(c.handler)) {
			unsafe = append(unsafe, c)
		}
		if c.progress {
			progressOn = append(progressOn, c)
		} else {
			progressOff = append(progressOff, c)
		}
	}

	// Evidence: one line per condition, ✓ met, ✗ not met, ? unknown.
	var ev []string
	cond1 := len(unsafe) > 0 || len(toUnsafe) > 0
	switch {
	case len(unsafe) > 0:
		ev = append(ev, fmt.Sprintf("✓ session.serialize_handler = %s (%s)", unsafe[0].handler, unsafe[0].handlerSrc))
	case len(toUnsafe) > 0:
		ev = append(ev, fmt.Sprintf("✓ session.serialize_handler set to %s in code (%s:%d)", toUnsafe[0].value, s.rel(toUnsafe[0].file), toUnsafe[0].line))
	case len(ctxs) == 0:
		ev = append(ev, "? session.serialize_handler: couldn't read PHP's configuration")
	default:
		ev = append(ev, fmt.Sprintf("✗ session.serialize_handler is php in every configuration checked (%s)", names(ctxs)))
	}
	sw := toPHP[0]
	val := "php"
	if sw.value == "" {
		val = "a computed value"
	}
	ev = append(ev, fmt.Sprintf("✓ switched to %s at runtime with ini_set() (%s:%d)", val, s.rel(sw.file), sw.line))
	if n := len(toPHP) - 1; n > 0 {
		ev[len(ev)-1] += fmt.Sprintf(", and %d more", n)
	}
	ordered := sw.startLine > 0
	switch {
	case ordered:
		ev = append(ev, fmt.Sprintf("✓ before session_start() (same file, line %d)", sw.startLine))
	case sw.startedBefore:
		ev = append(ev, "? after session_start() in this file; another code path may run it first")
	default:
		ev = append(ev, "? session_start() isn't in the same file, so the order depends on how the app runs")
	}
	cond4 := len(progressOn) > 0 || len(ctxs) == 0
	switch {
	case len(progressOn) > 0:
		ev = append(ev, fmt.Sprintf("✓ session.upload_progress.enabled is on (%s)", progressOn[0].progressSrc))
	case len(ctxs) == 0:
		ev = append(ev, "? session.upload_progress.enabled: couldn't read PHP's configuration (it's on by default)")
	default:
		ev = append(ev, fmt.Sprintf("✗ session.upload_progress.enabled is off (%s)", progressOff[0].progressSrc))
	}

	fix := "Until PHP releases a fix, set session.upload_progress.enabled = 0 in php.ini or the PHP-FPM pool " +
		"(php_admin_flag[session.upload_progress.enabled] = off) and restart PHP-FPM or the web server. " +
		"Better still, remove the runtime ini_set() of session.serialize_handler, or call it with the configured handler."
	impact := sessionCVE + " is an unpatched flaw in PHP's session upload progress. PHP says it is only reachable when " +
		"the configured serialize handler is php_binary or php_serialize, the app switches it to php with ini_set() " +
		"before session_start(), and upload progress is enabled."
	f := s.finding(sessionCheckID, engine.High, sw.file, "", ev, impact, fix, "php", "session", "vuln", strings.ToLower(sessionCVE))
	f.Evidence.Request = "read config and code"
	f.References = []string{"https://www.cve.org/CVERecord?id=" + sessionCVE}

	switch {
	case !cond4:
		f.Severity, f.Title = engine.Info, sessionCVE+": runtime handler switch found, mitigated (upload progress off)"
		f.Impact += " Upload progress is off everywhere checked, so it isn't reachable."
	case cond1 && ordered && sw.value != "":
		f.Title = sessionCVE + " is reachable: all four conditions hold"
	case cond1:
		f.Title = sessionCVE + " is likely reachable"
		f.Confidence = "low"
		f.Caveat = "likely: the code's order of calls couldn't be confirmed from one file"
	case len(ctxs) == 0:
		f.Severity, f.Title = engine.Medium, sessionCVE+": runtime handler switch found, configuration unknown"
		f.Confidence = "low"
		f.Caveat = "likely: PHP's configuration couldn't be read; check session.serialize_handler"
	default:
		f.Severity, f.Title = engine.Low, sessionCVE+": runtime handler switch found, not reachable now"
		f.Impact += " The configured handler is php, so the switch does nothing today; it becomes reachable if that changes."
	}
	return []engine.Finding{f}
}

func names(cs []sessionCtx) string {
	var out []string
	for _, c := range cs[:min(len(cs), 3)] {
		out = append(out, c.name)
	}
	if len(cs) > 3 {
		out = append(out, fmt.Sprintf("+%d more", len(cs)-3))
	}
	return strings.Join(out, ", ")
}

// phpSessionQuery prints the CLI's effective settings and where they came
// from. auto_prepend_file and auto_append_file are cleared so loading
// php.ini can't run any site code.
const phpSessionQuery = `echo json_encode(["ini" => php_ini_loaded_file(), "scanned" => php_ini_scanned_files(), ` +
	`"handler" => ini_get("session.serialize_handler"), "progress" => ini_get("session.upload_progress.enabled")]);`

// sessionConfig returns the contexts PHP runs in: the CLI as php reports
// it, then web server SAPIs and FPM pools read from their ini files.
func (s *scan) sessionConfig(ctx context.Context) []sessionCtx {
	var ctxs []sessionCtx
	var loaded string
	run := s.opts.Exec
	if run == nil {
		run = execOutput
	}
	cctx, cancel := context.WithTimeout(ctx, phpTimeout)
	defer cancel()
	out, err := run(cctx, cmp.Or(s.opts.PHP, "php"),
		"-d", "auto_prepend_file=", "-d", "auto_append_file=", "-d", "display_errors=0", "-r", phpSessionQuery)
	var q struct {
		Ini      any    `json:"ini"` // a path, or false when no php.ini is loaded
		Scanned  any    `json:"scanned"`
		Handler  string `json:"handler"`
		Progress string `json:"progress"`
	}
	if err == nil && json.Unmarshal(bytes.TrimSpace(out), &q) == nil {
		loaded, _ = q.Ini.(string)
		src := "php CLI"
		if loaded != "" {
			src = "php CLI, " + s.rel(loaded)
		}
		ctxs = append(ctxs, sessionCtx{
			name: "CLI", handler: cmp.Or(q.Handler, "php"), handlerSrc: src,
			progress: iniBool(q.Progress), progressSrc: src,
		})
	}

	root := cmp.Or(s.opts.ConfigRoot, "/")
	in := func(p string) string { return filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(p, "/"))) }
	seen := map[string]bool{}

	// Debian and Ubuntu keep one ini tree per SAPI next to the CLI's.
	var fpmBase *sessionCtx
	if m := debianCLIIni.FindStringSubmatch(filepath.ToSlash(loaded)); m != nil {
		for _, sapi := range []string{"fpm", "apache2", "cgi"} {
			dir := in(m[1] + "/" + sapi)
			ini := filepath.Join(dir, "php.ini")
			if _, err := os.Stat(ini); err != nil {
				continue
			}
			c := sessionCtx{name: sapi, handler: "php", handlerSrc: "default", progress: true, progressSrc: "default", web: true}
			files := append([]string{ini}, globSorted(filepath.Join(dir, "conf.d", "*.ini"))...)
			for _, f := range files {
				applyKV(&c, s.rel(f), parseKV(f, iniLine))
			}
			if sapi == "fpm" {
				base := c
				fpmBase = &base
				for _, pool := range globSorted(filepath.Join(dir, "pool.d", "*.conf")) {
					seen[pool] = true
					ctxs = append(ctxs, poolCtx(base, pool, s.rel(pool)))
				}
				continue
			}
			ctxs = append(ctxs, c)
		}
	}

	// FPM pools elsewhere (RHEL, Alpine, the official Docker images) share
	// the CLI's ini files, so they start from the CLI's settings.
	base := sessionCtx{name: "fpm", handler: "php", handlerSrc: "default", progress: true, progressSrc: "default"}
	switch {
	case fpmBase != nil:
		base = *fpmBase
	case len(ctxs) > 0:
		base = ctxs[0]
	}
	for _, pattern := range []string{"etc/php-fpm.d/*.conf", "etc/php*/php-fpm.d/*.conf", "usr/local/etc/php-fpm.d/*.conf"} {
		for _, pool := range globSorted(in(pattern)) {
			if !seen[pool] {
				seen[pool] = true
				ctxs = append(ctxs, poolCtx(base, pool, s.rel(pool)))
			}
		}
	}
	return ctxs
}

func poolCtx(base sessionCtx, path, rel string) sessionCtx {
	c := base
	c.web = true
	c.name = "FPM pool " + strings.TrimSuffix(filepath.Base(path), ".conf")
	applyKV(&c, rel, parseKV(path, poolLine))
	return c
}

// override is a per-directory settings file in the site.
type override struct {
	path string
	rel  string // for evidence
	kind string // ".user.ini" or ".htaccess"
	kv   map[string]string
}

// applyOverrides layers site overrides on the SAPI they apply to: .user.ini
// on FPM and CGI, .htaccess on mod_php (falling back to the first context).
// An override at the web root covers the whole site, so it replaces its
// base context; one deeper only covers its folder, so it's added.
func applyOverrides(ctxs []sessionCtx, ovs []override, webRoot string) []sessionCtx {
	for _, o := range ovs {
		i := slices.IndexFunc(ctxs, func(c sessionCtx) bool {
			if o.kind == ".htaccess" {
				return c.name == "apache2"
			}
			return strings.HasPrefix(c.name, "FPM") || c.name == "fpm" || c.name == "cgi"
		})
		if i < 0 && len(ctxs) > 0 {
			i = 0
		}
		base := sessionCtx{handler: "php", handlerSrc: "default", progress: true, progressSrc: "default"}
		if i >= 0 {
			base = ctxs[i]
		}
		c := base
		c.name = o.kind + " " + filepath.Dir(o.path)
		applyKV(&c, o.rel, o.kv)
		if i >= 0 && filepath.Dir(o.path) == webRoot {
			ctxs[i] = c
		} else {
			ctxs = append(ctxs, c)
		}
	}
	return ctxs
}

// applyKV applies the two settings found in kv, if any.
func applyKV(c *sessionCtx, src string, kv map[string]string) {
	if v, ok := kv["session.serialize_handler"]; ok {
		c.handler, c.handlerSrc, c.handlerSet = cmp.Or(v, "php"), src, true
	}
	if v, ok := kv["session.upload_progress.enabled"]; ok {
		c.progress, c.progressSrc, c.progressSet = iniBool(v), src, true
	}
}

// parseKV reads key = value settings from an ini file or FPM pool.
func parseKV(path string, line *regexp.Regexp) map[string]string {
	b, err := readHead(path, maxRead)
	if err != nil {
		return nil
	}
	kv := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l[0] == ';' || l[0] == '#' || l[0] == '[' {
			continue
		}
		if m := line.FindStringSubmatch(l); m != nil {
			kv[strings.ToLower(m[1])] = iniValue(m[2])
		}
	}
	return kv
}

// iniValue strips a trailing ; comment and surrounding quotes.
func iniValue(v string) string {
	if i := strings.Index(v, " ;"); i >= 0 {
		v = v[:i]
	}
	return strings.Trim(strings.TrimSpace(v), `"'`)
}

func iniBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "off", "false", "no", "none":
		return false
	}
	return true
}

func globSorted(pattern string) []string {
	m, _ := filepath.Glob(pattern)
	slices.Sort(m)
	return m
}

// sessionCode finds runtime switches of session.serialize_handler in the
// site's PHP files, and .user.ini/.htaccess overrides of the two settings.
// Unlike the stray-file walk it includes vendor/: libraries manage
// sessions too.
func (s *scan) sessionCode(ctx context.Context) ([]handlerSwitch, []override) {
	var switches []handlerSwitch
	var ovs []override
	entries := 0
	_ = filepath.WalkDir(s.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entries++; entries > s.opts.MaxEntries {
			return fs.SkipAll
		}
		if entries%1024 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		name := d.Name()
		if d.IsDir() {
			switch {
			case p == s.root:
			case name == "node_modules" || name == ".git" || name == ".svn" || name == ".hg":
				return fs.SkipDir
			case name == "cache" && filepath.Base(filepath.Dir(p)) == "wp-content":
				return fs.SkipDir
			case yearDir.MatchString(name) && filepath.Base(filepath.Dir(p)) == "uploads":
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		switch {
		case name == ".user.ini":
			if kv := parseKV(p, iniLine); hasSessionKey(kv) {
				ovs = append(ovs, override{path: p, rel: s.rel(p), kind: ".user.ini", kv: kv})
			}
		case name == ".htaccess":
			if kv := parseKV(p, htaccessLine); hasSessionKey(kv) {
				ovs = append(ovs, override{path: p, rel: s.rel(p), kind: ".htaccess", kv: kv})
			}
		case strings.HasSuffix(strings.ToLower(name), ".php"):
			b, err := readHead(p, maxRead)
			if err != nil || !bytes.Contains(b, []byte("serialize_handler")) {
				return nil
			}
			switches = append(switches, findSwitches(p, b)...)
		}
		return nil
	})
	// Literal switches to php first, ones confirmed before session_start()
	// first among those, so the evidence shows the strongest case.
	slices.SortStableFunc(switches, func(a, b handlerSwitch) int {
		return cmp.Or(
			cmp.Compare(rankSwitch(a), rankSwitch(b)),
			strings.Compare(a.file, b.file),
			cmp.Compare(a.line, b.line))
	})
	return switches, ovs
}

func rankSwitch(sw handlerSwitch) int {
	r := 0
	if sw.value == "" {
		r += 2
	}
	if sw.startLine == 0 {
		r++
	}
	return r
}

func hasSessionKey(kv map[string]string) bool {
	_, a := kv["session.serialize_handler"]
	_, b := kv["session.upload_progress.enabled"]
	return a || b
}

// findSwitches finds ini_set('session.serialize_handler', …) calls in PHP
// source, ignoring comments, and where session_start() sits relative to
// each.
func findSwitches(path string, src []byte) []handlerSwitch {
	code, inString := scanPHP(src)
	var starts [][]int
	for _, st := range sessionStart.FindAllIndex(code, -1) {
		if !inString[st[0]] {
			starts = append(starts, st)
		}
	}
	var out []handlerSwitch
	for _, m := range iniSetHandler.FindAllSubmatchIndex(code, -1) {
		if inString[m[0]] {
			continue // text that mentions the call, not the call
		}
		sw := handlerSwitch{file: path, line: lineAt(code, m[0])}
		if lit := literalArg.FindSubmatch(code[m[4]:m[5]]); lit != nil {
			sw.value = string(lit[1])
		}
		for _, st := range starts {
			if st[0] > m[1] {
				sw.startLine = lineAt(code, st[0])
				break
			}
			sw.startedBefore = true
		}
		if sw.startLine > 0 {
			sw.startedBefore = false
		}
		out = append(out, sw)
	}
	return out
}

func lineAt(b []byte, off int) int { return bytes.Count(b[:off], []byte("\n")) + 1 }

// stripPHPComments blanks out //, # and /* */ comments while keeping line
// breaks and string literals, so line numbers still match the file.
func stripPHPComments(src []byte) []byte {
	out, _ := scanPHP(src)
	return out
}

// scanPHP returns src with comments blanked (see stripPHPComments) and a
// mask of the bytes inside string literals, quotes included.
func scanPHP(src []byte) ([]byte, []bool) {
	out := make([]byte, len(src))
	copy(out, src)
	inString := make([]bool, len(src)+1)
	blank := func(i int) {
		if out[i] != '\n' {
			out[i] = ' '
		}
	}
	for i := 0; i < len(out); i++ {
		switch c := out[i]; {
		case c == '\'' || c == '"':
			start := i
			for i++; i < len(out) && out[i] != c; i++ {
				if out[i] == '\\' {
					i++
				}
			}
			for j := start; j <= i && j < len(out); j++ {
				inString[j] = true
			}
		case c == '#' || (c == '/' && i+1 < len(out) && out[i+1] == '/'):
			for ; i < len(out) && out[i] != '\n'; i++ {
				// A closing ?> ends a line comment too.
				if out[i] == '?' && i+1 < len(out) && out[i+1] == '>' {
					break
				}
				blank(i)
			}
		case c == '/' && i+1 < len(out) && out[i+1] == '*':
			for ; i < len(out); i++ {
				if out[i] == '*' && i+1 < len(out) && out[i+1] == '/' {
					blank(i)
					blank(i + 1)
					i++
					break
				}
				blank(i)
			}
		}
	}
	return out, inString
}
