// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package checktest

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/matchers"
)

// Prefixes are the ID prefixes a check may use, one per area. A new area
// adds its prefix here, so IDs stay grouped and never collide with the
// IDs vulnerability matching and local scans emit (vuln-*, local-*).
var Prefixes = map[string]string{
	"leak":    "leak",      // files and folders that should not be public
	"wp":      "wordpress", // WordPress
	"php":     "php",       // PHP and its tools
	"laravel": "laravel",   // Laravel
	"hdr":     "headers",   // response headers and cookies
	"tls":     "tls",       // HTTPS and certificates
	"srv":     "server",    // web server pages such as server-status
}

// QuickBudget is the most distinct paths the quick profile may request
// across all checks, so a quick scan stays a few seconds at the default
// rate.
const QuickBudget = 30

// Issue is one lint rule a check breaks.
type Issue struct {
	File    string // check or fixture file; empty for rules about the whole set
	Check   string // check ID, when known
	Rule    string // id, method, query, baseline, reference, fixtures, fix-server, budget or load
	Message string
}

func (i Issue) String() string {
	where := i.File
	if where == "" {
		where = "checks"
	}
	return fmt.Sprintf("%s: %s: %s", where, i.Rule, i.Message)
}

var kebab = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)+$`)

// Lint checks every check in fsys against the rules for checks Tuner
// ships: IDs, polite GET-only requests, guards against soft-404 pages,
// references, fixtures, well-formed server snippets and the quick
// profile's request budget. A check that fails to load is the only issue
// reported, since nothing else can be read.
func Lint(fsys fs.FS) []Issue {
	all, err := engine.LoadChecks(fsys)
	if err != nil {
		return []Issue{{Rule: "load", Message: err.Error()}}
	}
	var out []Issue
	quick := map[string][]string{} // path → quick checks requesting it
	for _, c := range all {
		out = append(out, LintCheck(fsys, c)...)
		if c.Profile == engine.ProfileQuick {
			for _, p := range c.Request.Path {
				quick[p] = append(quick[p], c.ID)
			}
		}
	}
	if len(quick) > QuickBudget {
		out = append(out, Issue{Rule: "budget", Message: fmt.Sprintf(
			"the quick profile requests %d distinct paths, more than %d; move a check to profile: default", len(quick), QuickBudget)})
	}
	return out
}

// LintCheck checks one check, loaded from fsys, and its fixture file.
func LintCheck(fsys fs.FS, c *engine.Check) []Issue {
	var out []Issue
	add := func(rule, format string, a ...any) {
		out = append(out, Issue{File: c.File, Check: c.ID, Rule: rule, Message: fmt.Sprintf(format, a...)})
	}

	if msg := lintID(c.ID); msg != "" {
		add("id", "%s", msg)
	}
	if m := strings.ToUpper(c.Request.Method); m != "GET" && m != "HEAD" {
		add("method", "request.method %s: checks only read, so use GET or HEAD", c.Request.Method)
	}
	for _, p := range c.Request.Path {
		if msg := lintPath(p); msg != "" {
			add("query", "request.path %q: %s", p, msg)
		}
	}
	if slices.ContainsFunc(c.Request.Path, func(p string) bool { return p != "/" }) && !guarded(c.Match) {
		add("baseline", "a path other than / needs not_baseline: true or a regex, words or magic matcher, "+
			"so a site that answers every URL with the same page doesn't fire it")
	}
	if !slices.ContainsFunc(c.References, func(r string) bool { return strings.HasPrefix(r, "https://") }) {
		add("reference", "needs at least one https:// reference")
	}
	if msg := nginxSyntax(c.FixServer.Nginx); msg != "" {
		add("fix-server", "fix_server.nginx: %s", msg)
	}
	if msg := apacheSyntax(c.FixServer.Apache); msg != "" {
		add("fix-server", "fix_server.apache: %s", msg)
	}

	name := strings.TrimSuffix(c.File, ".yaml") + "_test.yaml"
	fixture := func(format string, a ...any) {
		out = append(out, Issue{File: name, Check: c.ID, Rule: "fixtures", Message: fmt.Sprintf(format, a...)})
	}
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		fixture("missing: every check needs positive and negative cases")
		return out
	}
	var fx File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	switch err := dec.Decode(&fx); {
	case err != nil:
		fixture("%v", err)
	case len(fx.Positive) == 0 || len(fx.Negative) == 0:
		fixture("needs at least one positive and one negative case (has %d and %d)", len(fx.Positive), len(fx.Negative))
	}
	return out
}

// lintID returns why id is not a good check ID, or "".
func lintID(id string) string {
	if !kebab.MatchString(id) {
		return fmt.Sprintf("id %q: use lower-case words joined by hyphens, e.g. leak-dotenv", id)
	}
	prefix, _, _ := strings.Cut(id, "-")
	if _, ok := Prefixes[prefix]; !ok {
		known := make([]string, 0, len(Prefixes))
		for p := range Prefixes {
			known = append(known, p+"-")
		}
		slices.Sort(known)
		return fmt.Sprintf("id %q: start it with one of %s", id, strings.Join(known, ", "))
	}
	if engine.IsAdvisorID(id) {
		return fmt.Sprintf("id %q: that prefix belongs to vulnerability matching or local scans", id)
	}
	return ""
}

// plainQuery is all a query value may hold: words, numbers and the
// punctuation of ordinary file and version names.
var plainQuery = regexp.MustCompile(`^[A-Za-z0-9_.,-]*$`)

// lintPath returns why a request path looks like an attack rather than a
// read of something the site already serves, or "". Checks never send
// payloads: no traversal, no encoded tricks, no query values with quotes,
// brackets or code.
func lintPath(p string) string {
	raw, query, _ := strings.Cut(p, "?")
	lower := strings.ToLower(raw)
	for _, bad := range []string{"%00", "%2e", "%2f", "%5c", "\\", "<", ">", "'", `"`} {
		if strings.Contains(lower, bad) {
			return fmt.Sprintf("%q in the path looks like a payload; checks only read what a site already serves", bad)
		}
	}
	if slices.Contains(strings.Split(raw, "/"), "..") {
		return "path traversal (..) is not allowed"
	}
	if strings.Contains(strings.ReplaceAll(raw, "{{host}}", ""), "{{") {
		return "only {{host}} may be templated"
	}
	if query == "" {
		return ""
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return "query string does not parse: " + err.Error()
	}
	for k, vs := range values {
		for _, v := range append(vs, k) {
			if !plainQuery.MatchString(v) || strings.Contains(v, "..") {
				return fmt.Sprintf("query %q looks like a payload; use plain words and numbers", k+"="+strings.Join(vs, ","))
			}
		}
	}
	return ""
}

// guarded reports whether a match block can tell a real file from a page
// served for every URL: it compares with the soft-404 baseline or looks
// for content only the real thing has. With an any block and no guard in
// all, every alternative needs a guard of its own.
func guarded(b matchers.Block) bool {
	if slices.ContainsFunc(b.All, specific) {
		return true
	}
	return len(b.Any) > 0 && !slices.ContainsFunc(b.Any, func(m matchers.Matcher) bool { return !specific(m) })
}

func specific(m matchers.Matcher) bool {
	return m.NotBaseline || m.Regex != "" || len(m.Words) > 0 || m.Magic != ""
}

// nginxSyntax returns what is wrong with an nginx snippet, or "": braces
// must balance and every directive must end with ; or open a block.
// Quotes and comments are skipped, as nginx reads them.
func nginxSyntax(s string) string {
	depth, line := 0, 1
	pending := false // directive text since the last ; { or }
	var quote rune
	escaped, comment := false, false
	for _, r := range s {
		switch {
		case r == '\n':
			line++
			comment = false
			if quote == 0 {
				continue
			}
		case comment:
			continue
		case escaped:
			escaped = false
			continue
		case r == '\\':
			escaped = true
			pending = true
			continue
		case quote != 0:
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '"', '\'':
			quote, pending = r, true
		case '#':
			comment = true
		case ';':
			if !pending {
				return fmt.Sprintf("line %d: empty directive", line)
			}
			pending = false
		case '{':
			depth++
			pending = false
		case '}':
			if pending {
				return fmt.Sprintf("line %d: directive before } has no ;", line)
			}
			if depth--; depth < 0 {
				return fmt.Sprintf("line %d: } without {", line)
			}
		case ' ', '\t', '\r', '\n':
		default:
			pending = true
		}
	}
	switch {
	case quote != 0:
		return "unclosed quote"
	case depth > 0:
		return fmt.Sprintf("%d unclosed {", depth)
	case pending:
		return "last directive has no ;"
	}
	return ""
}

// apacheTag finds section tags such as <FilesMatch "^\."> and </Files>.
var apacheTag = regexp.MustCompile(`<(/?)([A-Za-z][A-Za-z0-9]*)(?:\s+(?:"[^"]*"|[^>"])*)?>`)

// apacheSyntax returns what is wrong with an Apache snippet, or "":
// every section tag must be closed by its own end tag, in order.
func apacheSyntax(s string) string {
	var open []string
	for n, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, m := range apacheTag.FindAllStringSubmatch(line, -1) {
			name := strings.ToLower(m[2])
			if m[1] == "" {
				open = append(open, name)
				continue
			}
			if len(open) == 0 || open[len(open)-1] != name {
				return fmt.Sprintf("line %d: </%s> does not close an open section", n+1, m[2])
			}
			open = open[:len(open)-1]
		}
	}
	if len(open) > 0 {
		return fmt.Sprintf("<%s> is never closed", open[len(open)-1])
	}
	return ""
}
