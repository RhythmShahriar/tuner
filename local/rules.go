// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/matchers"
)

// Local rules are file checks written as data in rules/*.yaml: which
// files to look at, what to look for in them and what to say. Malware
// signatures and most stray-file checks are rules. A rule only reads
// files; nothing it matches is ever run.
//
// A rule file holds one rule:
//
//	id: local-malware-eval-base64       # unique
//	name: eval() of base64-decoded code # the finding's title; {file} is the file name
//	severity: critical                  # critical, high, medium, low or info
//	confidence: high                    # high (confirmed) or low (likely)
//	caveat: why it is only likely       # optional, for low confidence
//	tags: [malware, php]
//	scope: project                      # project (default) or web, the document root
//	files: ["**/*.php"]                 # globs, any of them
//	exclude: ["vendor/**"]              # globs, none of them
//	max_size: 16384                     # bytes; larger files are skipped
//	match:                              # every part given must hold
//	  filename: '(?i)\.bak$'            # regex on the file name
//	  regex: ['…', '…']                 # regexes on the content, all of them
//	  words: [FilesMan, b374k]          # words in the content, any of them (any case)
//	  magic: "\x89PNG"                  # the content starts with this
//	  not: ['…']                        # regexes on the content, none of them
//	  secrets: [private-key]            # secrets of these kinds ("any" for any)
//	extract:
//	  secrets: true                     # attach the file's secrets, masked
//	  severity: high                    # and raise the severity when there are some
//	impact: …
//	fix: …
//	references: [https://…]
//
// Globs use forward slashes and match the path from the scope's root,
// ignoring case. * and ? stay within one folder, ** matches any number of
// folders (none included); [a-z] classes work as in path.Match.
//
// The web scope skips what the other stray-file checks skip: dependency
// folders, version control folders, wp-content/cache and the media
// library's year folders. The project scope skips version control and
// node_modules folders. Contents are the first 1 MiB of a file. Links
// aren't followed: a rule that reads content doesn't match a link,
// except one whose only content parts are not exemptions, since nothing
// shows the target is harmless. For the same reason not exemptions are
// skipped for files larger than what was read.
//
// Every rule has a fixture file rules/tests/<id>_test.yaml with at least
// one positive and one negative file; see rules_test.go.

//go:embed rules/*.yaml
var embeddedRules embed.FS

// Rule is a declarative local file check.
type Rule struct {
	ID         string          `yaml:"id"`
	Name       string          `yaml:"name"`
	Severity   engine.Severity `yaml:"severity"`
	Confidence string          `yaml:"confidence"`
	Caveat     string          `yaml:"caveat"`
	Tags       []string        `yaml:"tags"`
	Scope      string          `yaml:"scope"`
	Files      []string        `yaml:"files"`
	Exclude    []string        `yaml:"exclude"`
	MaxSize    int64           `yaml:"max_size"`
	Match      RuleMatch       `yaml:"match"`
	Extract    struct {
		Secrets  bool            `yaml:"secrets"`
		Severity engine.Severity `yaml:"severity"`
	} `yaml:"extract"`
	Impact     string   `yaml:"impact"`
	Fix        string   `yaml:"fix"`
	References []string `yaml:"references"`

	files    []glob // Files and Exclude, parsed
	exclude  []glob
	filename *regexp.Regexp
	regex    []*regexp.Regexp
	hints    [][][][]byte   // per regex, sets of lower-case literals; a match holds one of each set
	words    *regexp.Regexp // the words as one case-insensitive regex, to locate them
	lwords   [][]byte       // the words in lower case, for a cheap prefilter
	not      []*regexp.Regexp
	prune    []glob // exclude globs ending in /**, without it: whole folders to skip
}

// RuleMatch is what a rule looks for. Every part that is set must hold.
type RuleMatch struct {
	Filename string   `yaml:"filename"`
	Regex    []string `yaml:"regex"`
	Words    []string `yaml:"words"`
	Magic    string   `yaml:"magic"`
	Not      []string `yaml:"not"`
	Secrets  []string `yaml:"secrets"`
}

// Rule scopes.
const (
	scopeProject = "project"
	scopeWeb     = "web"
)

// Snippets in evidence are cut to this many bytes.
const maxSnippet = 80

// ParseRule reads and checks one rule file.
func ParseRule(data []byte) (*Rule, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var r Rule
	if err := dec.Decode(&r); err != nil {
		return nil, err
	}
	return &r, r.compile()
}

func (r *Rule) compile() error {
	switch {
	case !strings.HasPrefix(r.ID, "local-"):
		return fmt.Errorf("id %q must start with local-", r.ID)
	case r.Name == "":
		return errors.New("name is required")
	case !slices.Contains(engine.Severities, r.Severity):
		return fmt.Errorf("severity %q isn't one of critical, high, medium, low, info", r.Severity)
	case r.Extract.Severity != "" && !slices.Contains(engine.Severities, r.Extract.Severity):
		return fmt.Errorf("extract.severity %q isn't one of critical, high, medium, low, info", r.Extract.Severity)
	case r.Confidence != confidenceHigh && r.Confidence != confidenceLow:
		return fmt.Errorf("confidence %q must be high or low", r.Confidence)
	case len(r.Files) == 0:
		return errors.New("files is required")
	case r.Impact == "" || r.Fix == "":
		return errors.New("impact and fix are required")
	}
	if r.Scope == "" {
		r.Scope = scopeProject
	}
	if r.Scope != scopeProject && r.Scope != scopeWeb {
		return fmt.Errorf("scope %q must be project or web", r.Scope)
	}
	for _, g := range slices.Concat(r.Files, r.Exclude) {
		if err := checkGlob(g); err != nil {
			return err
		}
	}
	for _, g := range r.Files {
		r.files = append(r.files, newGlob(g))
	}
	for _, g := range r.Exclude {
		r.exclude = append(r.exclude, newGlob(g))
		if dir, ok := strings.CutSuffix(g, "/**"); ok {
			r.prune = append(r.prune, newGlob(dir))
		}
	}
	var err error
	compile := func(src string) *regexp.Regexp {
		re, e := regexp.Compile(src)
		if e != nil && err == nil {
			err = fmt.Errorf("regex %q: %w", src, e)
		}
		return re
	}
	if r.Match.Filename != "" {
		r.filename = compile(r.Match.Filename)
	}
	for _, src := range r.Match.Regex {
		r.regex = append(r.regex, compile(src))
		r.hints = append(r.hints, literalHints(src))
	}
	for _, src := range r.Match.Not {
		r.not = append(r.not, compile(src))
	}
	if len(r.Match.Words) > 0 {
		var alts []string
		for _, w := range r.Match.Words {
			if w == "" {
				return errors.New("words can't be empty")
			}
			alts = append(alts, regexp.QuoteMeta(w))
			r.lwords = append(r.lwords, bytes.ToLower([]byte(w)))
		}
		r.words = compile(`(?i)` + strings.Join(alts, "|"))
	}
	return err
}

// literalHints returns what a match of the regex must contain, in lower
// case: for each run of top-level parts that are literals or sets of
// literal alternatives, the set (a match holds one of them). Sets with a
// word shorter than 3 bytes aren't worth checking. nil means no hint, so the regex always
// runs.
func literalHints(src string) [][][]byte {
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return nil
	}
	re = re.Simplify()
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	parts := []*syntax.Regexp{re}
	if re.Op == syntax.OpConcat {
		parts = re.Sub
	}
	// Adjacent literal parts join up: the parser turns
	// gzinflate|gzdecode into gz(?:inflate|decode); "decode" alone
	// would let every file with base64_decode through.
	var out [][][]byte
	var run [][]byte
	flush := func() {
		if run != nil && !slices.ContainsFunc(run, func(a []byte) bool { return len(a) < 3 }) {
			out = append(out, run)
		}
		run = nil
	}
	for _, p := range parts {
		alts := literalAlts(p)
		switch {
		case alts == nil:
			flush()
		case run == nil:
			run = alts
		case len(run)*len(alts) > 64:
			flush()
			run = alts
		default:
			var next [][]byte
			for _, prefix := range run {
				for _, x := range alts {
					next = append(next, append(slices.Clone(prefix), x...))
				}
			}
			run = next
		}
	}
	flush()
	return out
}

// literalAlts returns the lower-case literals one of which re matches,
// or nil when re is anything else.
func literalAlts(re *syntax.Regexp) [][]byte {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	switch re.Op {
	case syntax.OpLiteral:
		return [][]byte{bytes.ToLower([]byte(string(re.Rune)))}
	case syntax.OpAlternate:
		var out [][]byte
		for _, sub := range re.Sub {
			a := literalAlts(sub)
			if a == nil {
				return nil
			}
			out = append(out, a...)
		}
		return out
	case syntax.OpConcat:
		// A factored alternation such as gz(?:inflate|decode).
		out := [][]byte{nil}
		for _, sub := range re.Sub {
			a := literalAlts(sub)
			if a == nil || len(out)*len(a) > 64 {
				return nil
			}
			var next [][]byte
			for _, prefix := range out {
				for _, x := range a {
					next = append(next, append(slices.Clone(prefix), x...))
				}
			}
			out = next
		}
		return out
	}
	return nil
}

// checkGlob reports a malformed glob.
func checkGlob(g string) error {
	if g == "" || strings.HasPrefix(g, "/") || strings.Contains(g, `\`) {
		return fmt.Errorf("glob %q: use a relative path with forward slashes", g)
	}
	for _, seg := range strings.Split(g, "/") {
		if _, err := path.Match(seg, ""); err != nil {
			return fmt.Errorf("glob %q: %w", g, err)
		}
	}
	return nil
}

// glob is a parsed glob (see the rules format).
type glob struct {
	segs []string          // lower-case segments
	last func(string) bool // matches the last path segment, when the glob doesn't end in **
}

func newGlob(g string) glob {
	segs := strings.Split(strings.ToLower(g), "/")
	out := glob{segs: segs}
	switch last := segs[len(segs)-1]; {
	case last == "**":
	case !strings.ContainsAny(last, `*?[`):
		out.last = func(name string) bool { return name == last }
	case last[0] == '*' && !strings.ContainsAny(last[1:], `*?[`):
		out.last = func(name string) bool { return strings.HasSuffix(name, last[1:]) }
	default:
		out.last = func(name string) bool { ok, _ := path.Match(last, name); return ok }
	}
	return out
}

// match matches a path's lower-case segments. Every file meets every
// rule's globs, so the last segment, usually *.php or a file name, is
// tried first: most paths fail there before any ** has to search.
func (g glob) match(p []string) bool {
	if g.last != nil && (len(p) == 0 || !g.last(p[len(p)-1])) {
		return false
	}
	return matchSegs(g.segs, p)
}

// globMatch matches a slash path against a glob, ignoring case.
func globMatch(g, p string) bool { return newGlob(g).match(strings.Split(strings.ToLower(p), "/")) }

func matchSegs(g, p []string) bool {
	for len(g) > 0 {
		if g[0] == "**" {
			for i := 0; i <= len(p); i++ {
				if matchSegs(g[1:], p[i:]) {
					return true
				}
			}
			return false
		}
		if len(p) == 0 {
			return false
		}
		if ok, _ := path.Match(g[0], p[0]); !ok {
			return false
		}
		g, p = g[1:], p[1:]
	}
	return len(p) == 0
}

// readsContent reports whether the rule needs the file's bytes to match.
func (r *Rule) readsContent() bool {
	return len(r.regex) > 0 || r.words != nil || r.Match.Magic != "" || len(r.not) > 0 || len(r.Match.Secrets) > 0
}

// wants reports whether the rule looks at the file at rel (its path's
// lower-case segments from the scope's root) by its path alone.
func (r *Rule) wants(rel []string, name string) bool {
	match := func(g glob) bool { return g.match(rel) }
	if !slices.ContainsFunc(r.files, match) || slices.ContainsFunc(r.exclude, match) {
		return false
	}
	return r.filename == nil || r.filename.MatchString(name)
}

// prunes reports whether the rule can't match anything under the folder
// at rel.
func (r *Rule) prunes(rel []string) bool {
	return slices.ContainsFunc(r.prune, func(dir glob) bool { return dir.match(rel) })
}

// exemptOnly reports whether the rule's only content parts are not
// regexes: it matches by path unless the content proves the file
// harmless.
func (r *Rule) exemptOnly() bool {
	return len(r.not) > 0 && len(r.regex) == 0 && r.words == nil && r.Match.Magic == "" && len(r.Match.Secrets) == 0
}

// match reports whether the file's content matches and where: the
// offset of the first regex or word match, or -1.
func (r *Rule) match(e *entry, f *fileData) (bool, int) {
	if r.MaxSize > 0 && f.size > r.MaxSize {
		return false, -1
	}
	if !r.readsContent() {
		return true, -1
	}
	// The walk doesn't follow links, so a link's content is unknown and
	// can't prove it harmless. A server that follows links still runs
	// the PHP a link named x.php in uploads points to.
	if e.typ&fs.ModeSymlink != 0 && r.exemptOnly() {
		return true, -1
	}
	if !e.regular() || f.head == nil {
		return false, -1
	}
	b := f.head
	if r.Match.Magic != "" && !bytes.HasPrefix(b, []byte(r.Match.Magic)) {
		return false, -1
	}
	at := -1
	if r.words != nil {
		lower := f.lower()
		if !slices.ContainsFunc(r.lwords, func(w []byte) bool { return bytes.Contains(lower, w) }) {
			return false, -1
		}
		if loc := r.words.FindIndex(b); loc != nil {
			at = loc[0]
		}
	}
	// Most files hold none of a regex's literal words; a lower-case
	// bytes.Contains is far cheaper than running the regex to find out.
	for _, sets := range r.hints {
		for _, set := range sets {
			if !slices.ContainsFunc(set, func(w []byte) bool { return bytes.Contains(f.lower(), w) }) {
				return false, -1
			}
		}
	}
	for i, re := range r.regex {
		loc := re.FindIndex(b)
		if loc == nil {
			return false, -1
		}
		if i == 0 {
			at = loc[0]
		}
	}
	// An exemption only holds when it saw the whole file. Anchored at
	// the end with \z, it would pass "<?php" padded past maxRead with
	// the payload after the padding.
	if f.size <= int64(len(b)) {
		for _, re := range r.not {
			if re.Match(b) {
				return false, -1
			}
		}
	}
	if len(r.Match.Secrets) > 0 {
		anyKind := slices.Contains(r.Match.Secrets, "any")
		if !slices.ContainsFunc(matchers.FindSecrets(b), func(s matchers.Secret) bool {
			return anyKind || slices.Contains(r.Match.Secrets, s.Kind)
		}) {
			return false, -1
		}
	}
	return true, at
}

// finding builds the rule's finding for the file at e.
func (r *Rule) finding(s *scan, e *entry, f *fileData, at int) engine.Finding {
	ev := []string{s.rel(e.path) + sizeNote(f.size)}
	if e.typ&fs.ModeSymlink != 0 {
		target, err := os.Readlink(e.path)
		if err != nil {
			target = "an unreadable target"
		}
		ev = append(ev, "a link to "+snippet([]byte(target), 0)+", not followed")
	}
	if f.size > int64(len(f.head)) && f.head != nil && len(r.not) > 0 {
		ev = append(ev, "only the first 1 MB was read, so the file can't be shown to be harmless")
	}
	if at >= 0 {
		ev = append(ev, fmt.Sprintf("%s: %s (line %d)", r.Name, snippet(f.head, at), lineAt(f.head, at)))
	}
	sev := r.Severity
	var sec []matchers.Secret
	if r.Extract.Secrets && f.head != nil {
		if sec = matchers.FindSecrets(f.head); len(sec) > 0 {
			ev = append(ev, fmt.Sprintf("%d secrets (masked below)", len(sec)))
			if r.Extract.Severity != "" {
				sev = r.Extract.Severity
			}
		}
	}
	title := strings.ReplaceAll(r.Name, "{file}", e.name)
	out := s.finding(r.ID, sev, e.path, title, ev, r.Impact, r.Fix, r.Tags...)
	out.Confidence, out.Caveat = engine.Confidence(r.Confidence), r.Caveat
	out.Evidence.Secrets = sec
	out.References = r.References
	return out
}

// snippet is the matched text from at to the end of its line, with
// secrets masked and control and format characters replaced, cut to
// maxSnippet bytes. Format characters include the bidi overrides that
// would reorder how a crafted line shows in a terminal.
// Secrets are masked before cutting, so a cut can't reveal part of one.
func snippet(b []byte, at int) string {
	end := at + 4*maxSnippet
	if nl := bytes.IndexByte(b[at:], '\n'); nl >= 0 && at+nl < end {
		end = at + nl
	}
	end = min(end, len(b))
	s := cleanText(strings.TrimRight(string(b[at:end]), "\r"), false)
	s = matchers.Redact(s)
	if len(s) > maxSnippet {
		cut := maxSnippet
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

// LoadRules reads every rule file (*.yaml, not *_test.yaml) at the root
// of fsys. A file that doesn't parse is reported and left out; so is a
// second rule with an ID already taken.
func LoadRules(fsys fs.FS) ([]*Rule, []error) {
	names, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, []error{err}
	}
	var rules []*Rule
	var errs []error
	seen := map[string]bool{}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.yaml") {
			continue
		}
		data, err := fs.ReadFile(fsys, name)
		if err == nil {
			var r *Rule
			if r, err = ParseRule(data); err == nil {
				if seen[r.ID] {
					err = fmt.Errorf("id %s is already used", r.ID)
				} else {
					seen[r.ID] = true
					rules = append(rules, r)
				}
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return rules, errs
}

var builtinRules = sync.OnceValues(func() ([]*Rule, []error) {
	sub, err := fs.Sub(embeddedRules, "rules")
	if err != nil {
		return nil, []error{err}
	}
	return LoadRules(sub)
})

// BuiltinRules returns the rules built into Tuner.
func BuiltinRules() []*Rule {
	rules, _ := builtinRules()
	return rules
}

// rules returns the rules for this scan: Options.Rules when set, else
// the built-in ones. Rule files that don't load become warnings.
func (s *scan) rules() []*Rule {
	if s.opts.Rules == nil {
		rules, errs := builtinRules()
		for _, err := range errs {
			s.warn("local rules: %v", err)
		}
		return rules
	}
	rules, errs := LoadRules(s.opts.Rules)
	for _, err := range errs {
		s.warn("local rules: %v", err)
	}
	return rules
}

// rulesVisitor runs the project-scope rules. Web-scope rules run in the
// stray-file visitor, which already skips what they should skip.
type rulesVisitor struct {
	s     *scan
	rules []*Rule
	collector
}

func (v *rulesVisitor) root() string { return v.s.root }
func (v *rulesVisitor) checks() int  { return len(v.rules) }

// projectPrunes are folders no project rule looks in.
func projectPrunes(name string) bool {
	switch name {
	case ".git", ".svn", ".hg", "node_modules":
		return true
	}
	return false
}

func (v *rulesVisitor) enter(e *entry) bool {
	if projectPrunes(e.name) {
		return false
	}
	rel := relSegs(v.s.root, e.path)
	return slices.ContainsFunc(v.rules, func(r *Rule) bool { return !r.prunes(rel) })
}

func (v *rulesVisitor) need(e *entry) need {
	return rulesNeed(v.rules, relSegs(v.s.root, e.path), e)
}

func (v *rulesVisitor) visit(e *entry, f *fileData) {
	v.add(runRules(v.s, v.rules, relSegs(v.s.root, e.path), e, f)...)
}

// relSegs is p relative to root, in lower case, split into segments.
func relSegs(root, p string) []string {
	r, err := filepath.Rel(root, p)
	if err != nil {
		return nil
	}
	return strings.Split(strings.ToLower(filepath.ToSlash(r)), "/")
}

// rulesNeed says what the rules need from the file at rel.
func rulesNeed(rules []*Rule, rel []string, e *entry) need {
	var n need
	for _, r := range rules {
		if r.wants(rel, e.name) {
			n |= needVisit
			if r.readsContent() || r.Extract.Secrets {
				n |= needHead
			}
		}
	}
	return n
}

// runRules returns the findings of the rules that match the file.
func runRules(s *scan, rules []*Rule, rel []string, e *entry, f *fileData) []engine.Finding {
	var out []engine.Finding
	for _, r := range rules {
		if !r.wants(rel, e.name) {
			continue
		}
		if ok, at := r.match(e, f); ok {
			out = append(out, r.finding(s, e, f, at))
		}
	}
	return out
}
