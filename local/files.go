// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/matchers"
)

var (
	// Database dumps have their own rule, even compressed.
	sqlDump = regexp.MustCompile(`(?i)\.(sql|mysql|pgsql)(\.(gz|bz2|xz|zip|7z|zst))?$|\.sqlite3?$`)
	archive = regexp.MustCompile(`(?i)\.(zip|tar|tgz|tbz2?|txz|gz|bz2|xz|7z|rar|wpress)$`)
	siteish = regexp.MustCompile(`(?i)backup|bak|site|www|html|public|wordpress|wp|db|database|dump|full|export|migrat|old|copy|archive|snapshot|20[0-9]{2}`)
	yearDir = regexp.MustCompile(`^[0-9]{4}$`)
)

// strayChecks are the stray-file checks written in Go, for the summary's
// count. The others are web-scope rules in rules/*.yaml.
var strayChecks = []string{"local-vcs-dir", "local-db-admin", "local-backup-archive", "local-composer-auth"}

// strayVisitor looks for files that shouldn't be in the document root.
// Nothing is known to be served: remote checks confirm that, so
// findings say "in the web root". It also runs the web-scope rules, so
// they skip the same folders.
type strayVisitor struct {
	s     *scan
	rules []*Rule // web-scope rules
	collector
}

func (v *strayVisitor) root() string { return v.s.web }
func (v *strayVisitor) checks() int  { return len(strayChecks) + len(v.rules) }

func (v *strayVisitor) enter(e *entry) bool {
	f, skip := v.s.dir(e.path, e.name)
	if f != nil {
		v.add(*f)
	}
	return !skip
}

// need reads only the files a check looks inside; the rest are judged
// by name and size.
func (v *strayVisitor) need(e *entry) need {
	n := needVisit | rulesNeed(v.rules, relSegs(v.s.web, e.path), e)
	if strings.EqualFold(e.name, "auth.json") {
		n |= needHead
	}
	return n
}

func (v *strayVisitor) visit(e *entry, f *fileData) {
	if x := v.s.file(e, f); x != nil {
		v.add(*x)
	}
	v.add(runRules(v.s, v.rules, relSegs(v.s.web, e.path), e, f)...)
}

// dir reports a directory worth a finding and whether to skip its contents.
func (s *scan) dir(p, name string) (*engine.Finding, bool) {
	lower := strings.ToLower(name)
	parent := filepath.Base(filepath.Dir(p))
	switch {
	case lower == ".git" || lower == ".svn" || lower == ".hg":
		f := s.finding("local-vcs-dir", engine.Medium, p, "Version control folder "+name+" in the web root",
			[]string{s.rel(p)},
			"If the web server serves it, the full source code and its history can be downloaded, often with old passwords and keys.",
			"Deploy without the "+name+" folder, or block it in the server config (nginx: location ~ /\\.(git|svn|hg) { deny all; }).",
			"leak", "source")
		return &f, true
	case lower == "phpmyadmin" || lower == "pma":
		if _, err := os.Stat(filepath.Join(p, "index.php")); err == nil {
			f := s.finding("local-db-admin", engine.Medium, p, "phpMyAdmin in the web root", []string{s.rel(p)},
				"A database login page on the public site invites password guessing and exposes any phpMyAdmin vulnerabilities.",
				"Remove it, or restrict it to your IP address or a VPN.", "php", "database", "admin")
			return &f, true
		}
	case lower == "node_modules" || lower == "vendor" || lower == "bower_components":
		return nil, true // third-party code; composer.lock covers vendor
	case lower == "cache" && parent == "wp-content":
		return nil, true
	case yearDir.MatchString(name) && parent == "uploads":
		return nil, true // media library; backup plugins use other folders
	}
	return nil, false
}

// file reports a file worth a finding, for the stray-file checks that
// need more than a rule can say. Only regular files were read: links
// aren't followed in the web root, so f.head is nil for them.
func (s *scan) file(e *entry, f *fileData) *engine.Finding {
	p, name := e.path, e.name
	lower := strings.ToLower(name)
	// Plugins and themes ship their own archives, examples and tests.
	inComponent := strings.Contains(filepath.ToSlash(p), "/wp-content/plugins/") || strings.Contains(filepath.ToSlash(p), "/wp-content/themes/")
	ev := []string{s.rel(p) + sizeNote(f.size)}

	switch {
	case archive.MatchString(name) && !sqlDump.MatchString(name) && !inComponent && (lower == "wp-content.zip" || strings.HasSuffix(lower, ".wpress") ||
		filepath.Dir(p) == s.web || siteish.MatchString(name) || strings.Contains(lower, strings.ToLower(filepath.Base(s.root)))):
		return s.findingPtr("local-backup-archive", engine.High, p, "Backup archive in the web root", ev,
			"Site backups usually contain the whole site including wp-config.php or .env. Backup plugins protect their folders with .htaccess, which nginx ignores.",
			"Store backups outside the web root or off the server and delete old ones.", "leak", "backup")

	case lower == "auth.json" && !inComponent:
		var sec []matchers.Secret
		if f.head != nil {
			sec = matchers.FindSecrets(f.head)
		}
		if len(sec) > 0 || bytes.Contains(f.head, []byte("github-oauth")) {
			x := s.finding("local-composer-auth", engine.High, p, "Composer auth.json in the web root", ev,
				"auth.json holds tokens for GitHub and private package repositories.",
				"Move it out of the web root (use COMPOSER_AUTH or ~/.composer/auth.json) and rotate the tokens.",
				"leak", "secrets")
			x.Evidence.Secrets = sec
			return &x
		}
	}
	return nil
}

func (s *scan) findingPtr(id string, sev engine.Severity, p, title string, ev []string, impact, fix string, tags ...string) *engine.Finding {
	f := s.finding(id, sev, p, title, ev, impact, fix, tags...)
	return &f
}

// thousands renders n with comma separators, e.g. 250,000.
func thousands(n int) string {
	s := strconv.Itoa(n)
	start := 0
	if n < 0 {
		start = 1
	}
	for i := len(s) - 3; i > start; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func sizeNote(n int64) string {
	switch {
	case n < 0:
		return ""
	case n < 1<<10:
		return fmt.Sprintf(" (%d B)", n)
	case n < 1<<20:
		return fmt.Sprintf(" (%.1f KB)", float64(n)/(1<<10))
	case n < 1<<30:
		return fmt.Sprintf(" (%.1f MB)", float64(n)/(1<<20))
	}
	return fmt.Sprintf(" (%.1f GB)", float64(n)/(1<<30))
}
