// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

// WordPress reads plugin and theme headers from the first 8 KiB of a file;
// so does Tuner.
const headerBytes = 8 << 10

// Plugin folders with more top-level PHP files than this aren't searched
// further for the main file.
const maxPluginFiles = 50

var (
	wpVersionVar = regexp.MustCompile(`\$wp_version\s*=\s*['"]([^'"]+)['"]`)
	versionToken = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]*`)
	tablePrefix  = regexp.MustCompile(`\$table_prefix\s*=\s*['"]([^'"]*)['"]`)
	defineRe     = regexp.MustCompile(`(?is)\bdefine\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*,\s*(.*?)\s*\)\s*;`)
)

// The keys and salts wp-config.php should set, and the value the sample
// file ships with.
var (
	saltNames       = []string{"AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"}
	saltPlaceholder = "put your unique phrase here"
)

// Headers Tuner reads, matched like WordPress's get_file_data().
var headers = map[string]*regexp.Regexp{}

func init() {
	for _, name := range []string{"Plugin Name", "Theme Name", "Version"} {
		headers[name] = regexp.MustCompile(`(?mi)^[ \t/*#@]*` + regexp.QuoteMeta(name) + `:(.*)$`)
	}
}

// Includes other than wp-settings.php: settings may be defined there.
var includeRe = regexp.MustCompile(`(?i)\b(?:require|include)(?:_once)?\b[^;]*;`)

type wordpress struct {
	root       string
	version    string
	content    string // wp-content directory
	components []fingerprint.Component
}

// detectWordPress returns nil unless root is a WordPress install.
func (s *scan) detectWordPress(ctx context.Context, root string) *wordpress {
	b, err := s.readHead(filepath.Join(root, "wp-includes", "version.php"), 64<<10)
	if err != nil {
		return nil
	}
	wp := &wordpress{root: root, content: filepath.Join(root, "wp-content")}
	if m := wpVersionVar.FindSubmatch(b); m != nil {
		wp.version = string(m[1])
	}
	wp.components = append(s.plugins(ctx, filepath.Join(wp.content, "plugins")), s.themes(ctx, filepath.Join(wp.content, "themes"))...)
	return wp
}

// header reads a WordPress file header such as "Version:", the way
// get_file_data() does.
func header(b []byte, name string) (string, bool) {
	m := headers[name].FindSubmatch(b)
	if m == nil {
		return "", false
	}
	v := strings.TrimSpace(string(m[1]))
	v = strings.TrimSpace(strings.TrimSuffix(v, "*/"))
	return v, true
}

// headerVersion returns the version token of a "Version:" header.
func headerVersion(b []byte) string {
	v, _ := header(b, "Version")
	return versionToken.FindString(v)
}

// plugins reads each installed plugin's version from its main file's
// header: the installed version, unlike readme.txt's Stable tag.
func (s *scan) plugins(ctx context.Context, dir string) []fingerprint.Component {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []fingerprint.Component
	for _, e := range entries {
		if ctx.Err() != nil {
			return out
		}
		name := e.Name()
		switch {
		case e.IsDir() && !strings.HasPrefix(name, "."):
			if b := s.mainPluginFile(filepath.Join(dir, name), name); b != nil {
				out = append(out, fingerprint.Component{Type: "plugin", Slug: name, Version: headerVersion(b), Source: "plugin header"})
			}
		case e.Type().IsRegular() && strings.HasSuffix(name, ".php") && name != "index.php":
			// A single-file plugin, e.g. hello.php.
			if b, err := s.readHead(filepath.Join(dir, name), headerBytes); err == nil {
				if _, ok := header(b, "Plugin Name"); ok {
					out = append(out, fingerprint.Component{Type: "plugin", Slug: strings.TrimSuffix(name, ".php"), Version: headerVersion(b), Source: "plugin header"})
				}
			}
		}
	}
	return out
}

// mainPluginFile returns the head of the PHP file in dir with a "Plugin
// Name:" header, trying <slug>.php first, or nil if there is none.
func (s *scan) mainPluginFile(dir, slug string) []byte {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".php") {
			files = append(files, e.Name())
		}
	}
	slices.SortStableFunc(files, func(a, b string) int {
		return cmp.Compare(boolInt(a != slug+".php"), boolInt(b != slug+".php"))
	})
	for _, f := range files[:min(len(files), maxPluginFiles)] {
		b, err := s.readHead(filepath.Join(dir, f), headerBytes)
		if err != nil {
			continue
		}
		if _, ok := header(b, "Plugin Name"); ok {
			return b
		}
	}
	return nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// themes reads each theme's version from its style.css.
func (s *scan) themes(ctx context.Context, dir string) []fingerprint.Component {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []fingerprint.Component
	for _, e := range entries {
		if ctx.Err() != nil {
			return out
		}
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		b, err := s.readHead(filepath.Join(dir, e.Name(), "style.css"), headerBytes)
		if err != nil {
			continue
		}
		if _, ok := header(b, "Theme Name"); ok {
			out = append(out, fingerprint.Component{Type: "theme", Slug: e.Name(), Version: headerVersion(b), Source: "style.css"})
		}
	}
	return out
}

// muPlugins lists must-use plugins. They aren't matched against
// wordpress.org data: they're usually custom or host-provided code whose
// file names don't correspond to wordpress.org slugs.
func (s *scan) muPlugins() []engine.Finding {
	dir := filepath.Join(s.wp.content, "mu-plugins")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	s.checks++
	var list []string
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".php") {
			continue
		}
		item := e.Name()
		if b, err := s.readHead(filepath.Join(dir, e.Name()), headerBytes); err == nil {
			if name, ok := header(b, "Plugin Name"); ok && name != "" {
				item += " (" + name
				if v := headerVersion(b); v != "" {
					item += " " + v
				}
				item += ")"
			}
		}
		list = append(list, item)
	}
	if len(list) == 0 {
		return nil
	}
	return []engine.Finding{s.finding("local-wp-mu-plugins", engine.Info, dir,
		fmt.Sprintf("%d must-use plugin%s installed", len(list), plural(len(list))), list,
		"Must-use plugins always run and can't be disabled from the dashboard. They aren't checked against vulnerability data.",
		"Make sure each one is expected and kept up to date.", "wordpress")}
}

// wpConfig reviews wp-config.php without running it.
func (s *scan) wpConfig() []engine.Finding {
	path := filepath.Join(s.root, "wp-config.php")
	if _, err := os.Stat(path); err != nil {
		// WordPress also looks one level up, unless that's another install.
		up := filepath.Join(filepath.Dir(s.root), "wp-config.php")
		_, other := os.Stat(filepath.Join(filepath.Dir(s.root), "wp-settings.php"))
		if _, err := os.Stat(up); err != nil || other == nil {
			s.warn("wp-config.php not found, so its settings weren't checked")
			return nil
		}
		path = up
	}
	b, err := s.readHead(path, maxRead)
	if err != nil {
		if !isNotRegular(err) { // already warned
			s.warn("couldn't read wp-config.php: %v", err)
		}
		return nil
	}
	cfg := parseConfig(string(b))
	var out []engine.Finding
	s.checks += 6

	// Keys and salts.
	var weak []string
	seen := map[string]bool{}
	for _, name := range saltNames {
		v, ok := cfg.defines[name]
		lit, isLit := phpString(v)
		switch {
		case !ok:
			weak = append(weak, name+" not set")
		case !isLit:
			// Computed, e.g. getenv(); can't judge it.
		case lit == "" || lit == saltPlaceholder:
			weak = append(weak, name+" is the sample placeholder or empty"+cfg.at(name))
		case seen[lit]:
			weak = append(weak, name+" repeats another key's value"+cfg.at(name))
		}
		if isLit {
			seen[lit] = true
		}
	}
	if len(weak) > 0 {
		out = append(out, s.maybe(cfg, !slices.ContainsFunc(saltNames, cfg.defined), "local-wp-salts", engine.Medium, path,
			"WordPress keys and salts are not set", weak,
			"WordPress ignores placeholder, empty and duplicate keys and falls back to random salts stored in the database. "+
				"Anyone who reads the database (a leaked dump or an SQL injection) can then forge login cookies for any user.",
			"Generate fresh keys at https://api.wordpress.org/secret-key/1.1/salt/ and paste them into wp-config.php (or run: wp config shuffle-salts). Everyone is logged out once.",
			"wordpress", "config"))
	}

	// Debug mode.
	if on, _ := cfg.truthy("WP_DEBUG"); on {
		display, known := cfg.truthy("WP_DEBUG_DISPLAY")
		display = display || !known // WordPress shows errors unless told not to
		ev := []string{"WP_DEBUG is true" + cfg.at("WP_DEBUG")}
		sev := engine.Low
		if display {
			ev = append(ev, "WP_DEBUG_DISPLAY is not false, so errors are shown on pages")
			sev = engine.Medium
		}
		if v, ok := cfg.defines["WP_DEBUG_LOG"]; ok {
			if p, isStr := phpString(v); isStr && p != "" && p != "0" && p != "1" {
				ev = append(ev, "WP_DEBUG_LOG writes to "+p+cfg.at("WP_DEBUG_LOG"))
			} else if l, _ := cfg.truthy("WP_DEBUG_LOG"); l {
				ev = append(ev, "WP_DEBUG_LOG writes to wp-content/debug.log, which is public by default"+cfg.at("WP_DEBUG_LOG"))
				sev = engine.Medium
			}
		}
		out = append(out, s.finding("local-wp-debug", sev, path, "WordPress debug mode is on", ev,
			"Error messages reveal file paths, plugin internals and sometimes queries or secrets, which help attackers.",
			"Set WP_DEBUG to false in production. If you need logs, set WP_DEBUG_DISPLAY to false and point WP_DEBUG_LOG at a file outside the web root.",
			"wordpress", "config", "disclosure"))
	}

	// Dashboard file editor.
	edit, _ := cfg.truthy("DISALLOW_FILE_EDIT")
	mods, _ := cfg.truthy("DISALLOW_FILE_MODS")
	if !edit && !mods {
		out = append(out, s.maybe(cfg, true, "local-wp-file-edit", engine.Low, path,
			"The dashboard file editor is enabled", []string{"DISALLOW_FILE_EDIT is not set to true" + cfg.at("DISALLOW_FILE_EDIT")},
			"An attacker who gets into any administrator account can edit plugin and theme PHP and run code on the server.",
			"Add define( 'DISALLOW_FILE_EDIT', true ); to wp-config.php.",
			"wordpress", "config", "hardening"))
	}

	// Table prefix.
	if cfg.prefix == "wp_" {
		out = append(out, s.finding("local-wp-table-prefix", engine.Info, path,
			"Database tables use the default wp_ prefix", []string{"$table_prefix = 'wp_'" + lineNote(cfg.prefixLine)},
			"Automated SQL injection attacks assume wp_ table names. A custom prefix is minor defense in depth, not a fix.",
			"Use a custom prefix on new installs. Changing it on a live site means renaming tables and options, so only do it with a backup.",
			"wordpress", "config", "hardening"))
	}

	// HTTPS for the dashboard.
	if ssl, _ := cfg.truthy("FORCE_SSL_ADMIN"); !ssl {
		out = append(out, s.maybe(cfg, true, "local-wp-force-ssl-admin", engine.Info, path,
			"FORCE_SSL_ADMIN is not set", []string{"FORCE_SSL_ADMIN is not true" + cfg.at("FORCE_SSL_ADMIN")},
			"If the site can be reached over plain HTTP, logins and admin cookies could travel unencrypted. Most sites already redirect to HTTPS at the server.",
			"Add define( 'FORCE_SSL_ADMIN', true ); to wp-config.php once the site has a certificate.",
			"wordpress", "config", "hardening"))
	}

	// File permissions.
	if fi, err := os.Stat(path); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm()&0o004 != 0 {
		out = append(out, s.finding("local-wp-config-perms", engine.Low, path,
			"wp-config.php is readable by every user on the server",
			[]string{"mode " + fi.Mode().Perm().String()},
			"On shared servers, other accounts can read the database password and keys.",
			"Restrict it to the site's user and the web server, e.g. chmod 640 wp-config.php (or 600 when PHP runs as the site's user).",
			"wordpress", "config", "permissions"))
	}
	return out
}

// maybe builds a finding about a setting wp-config.php lacks. When the
// file includes others, the setting may be there: the finding is then
// marked likely rather than confirmed.
func (s *scan) maybe(cfg config, absent bool, id string, sev engine.Severity, path, title string, ev []string, impact, fix string, tags ...string) engine.Finding {
	f := s.finding(id, sev, path, title, ev, impact, fix, tags...)
	if absent && cfg.includes {
		f.Confidence = "low"
		f.Evidence.Matched = append(f.Evidence.Matched, "wp-config.php includes other files, which may set this")
	}
	return f
}

// config is what wp-config.php defines, read as text.
type config struct {
	defines map[string]string // name → raw PHP expression; the first definition wins
	lines   map[string]int    // name → line of that definition
	prefix  string
	// prefixLine is the line $table_prefix is set on, 0 if it isn't.
	prefixLine int
	// includes is true when the file loads other PHP files (besides
	// wp-settings.php) that may define what's missing here.
	includes bool
}

func parseConfig(src string) config {
	code := stripComments(src)
	c := config{defines: map[string]string{}, lines: map[string]int{}}
	for _, m := range defineRe.FindAllStringSubmatchIndex(code, -1) {
		name := code[m[2]:m[3]]
		if _, dup := c.defines[name]; !dup {
			c.defines[name] = strings.TrimSpace(code[m[4]:m[5]])
			c.lines[name] = lineAt([]byte(code), m[0])
		}
	}
	if m := tablePrefix.FindStringSubmatchIndex(code); m != nil {
		c.prefix = code[m[2]:m[3]]
		c.prefixLine = lineAt([]byte(code), m[0])
	}
	for _, m := range includeRe.FindAllString(code, -1) {
		if !strings.Contains(m, "wp-settings.php") {
			c.includes = true
		}
	}
	return c
}

// at renders where name is defined, e.g. " (line 14)", or "" when it isn't.
func (c config) at(name string) string { return lineNote(c.lines[name]) }

// lineNote renders a 1-based line number for evidence, or "" for 0.
// Findings have no line field yet, so it goes in the evidence text.
func lineNote(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf(" (line %d)", n)
}

func (c config) defined(name string) bool {
	_, ok := c.defines[name]
	return ok
}

// truthy evaluates a constant the way PHP would in a boolean context.
// known is false when it isn't defined or isn't a literal.
func (c config) truthy(name string) (value, known bool) {
	v, ok := c.defines[name]
	if !ok {
		return false, false
	}
	if s, ok := phpString(v); ok {
		return s != "" && s != "0", true
	}
	switch strings.ToLower(v) {
	case "true":
		return true, true
	case "false", "null":
		return false, true
	}
	if n, err := strconv.ParseFloat(v, 64); err == nil {
		return n != 0, true
	}
	return false, false
}

// phpString returns the value of a single- or double-quoted PHP string
// literal. Double-quoted strings with interpolation aren't literals.
func phpString(v string) (string, bool) {
	if len(v) < 2 || v[0] != v[len(v)-1] || (v[0] != '\'' && v[0] != '"') {
		return "", false
	}
	inner := v[1 : len(v)-1]
	if strings.ContainsRune(inner, rune(v[0])) && !strings.Contains(inner, `\`+string(v[0])) {
		return "", false // e.g. 'a' . 'b'
	}
	if v[0] == '"' && strings.Contains(inner, "$") {
		return "", false
	}
	return strings.NewReplacer(`\\`, `\`, `\'`, `'`, `\"`, `"`).Replace(inner), true
}

// stripComments removes PHP comments, leaving strings intact, so a
// commented-out define() doesn't count. Line breaks are kept so offsets
// in the result still give the file's line numbers.
func stripComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '\'' || c == '"':
			j := i + 1
			for j < len(src) && src[j] != c {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			j = min(j, len(src)-1)
			b.WriteString(src[i : j+1])
			i = j
		case c == '#' || (c == '/' && i+1 < len(src) && src[i+1] == '/'):
			for i < len(src) && src[i] != '\n' {
				i++
			}
			if i < len(src) {
				b.WriteByte('\n')
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return b.String()
			}
			b.WriteByte(' ')
			b.WriteString(strings.Repeat("\n", strings.Count(src[i+2:i+2+end], "\n")))
			i += 2 + end + 1
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
