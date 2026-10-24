// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/matchers"
)

// Small PHP files are read to spot phpinfo() pages; bigger ones aren't.
const maxPHPInfoSize = 16 << 10

var (
	// wp-config.php copies a server would send as plain text:
	// wp-config.php.bak, wp-config.old, .wp-config.php.swp, wp-config.php~ …
	wpConfigCopy = regexp.MustCompile(`(?i)^\.?wp-config(\.php)?[.~_-].*$`)
	// Editor and backup copies of PHP files, served as source.
	phpCopy   = regexp.MustCompile(`(?i)\.php(\.(bak|old|orig|save|saved|swp|swo|backup|copy|tmp|txt)|~)$`)
	sqlDump   = regexp.MustCompile(`(?i)\.(sql|mysql|pgsql)(\.(gz|bz2|xz|zip|7z|zst))?$|\.sqlite3?$`)
	archive   = regexp.MustCompile(`(?i)\.(zip|tar|tgz|tbz2?|txz|gz|bz2|xz|7z|rar|wpress)$`)
	siteish   = regexp.MustCompile(`(?i)backup|bak|site|www|html|public|wordpress|wp|db|database|dump|full|export|migrat|old|copy|archive|snapshot|20[0-9]{2}`)
	phpinfoFn = regexp.MustCompile(`(?i)\bphpinfo\s*\(`)
	infoName  = regexp.MustCompile(`(?i)^(php_?info|info|pinfo|pi|i|test|phptest|php)\.php$`)
	yearDir   = regexp.MustCompile(`^[0-9]{4}$`)
	envName   = regexp.MustCompile(`^\.env(\..+)?$`)
)

// .env variants that are templates, not real settings.
var envTemplates = []string{".env.example", ".env.sample", ".env.dist", ".env.template", ".env.defaults"}

// walk looks for files that shouldn't be in the document root. Nothing is
// known to be served: remote checks confirm that, so findings say "in the
// web root".
func (s *scan) walk(ctx context.Context) []engine.Finding {
	if _, err := os.Stat(s.web); err != nil {
		return nil
	}
	s.checks += 11
	var out []engine.Finding
	entries := 0
	err := filepath.WalkDir(s.web, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable: skip it, keep going
		}
		if entries++; entries > s.opts.MaxEntries {
			s.warn("stopped looking for stray files after %d entries; scan a smaller folder to cover the rest", s.opts.MaxEntries)
			return fs.SkipAll
		}
		if entries%1024 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		name := d.Name()
		if d.IsDir() {
			if p == s.web {
				return nil
			}
			f, skip := s.dir(p, name)
			if f != nil {
				out = append(out, *f)
			}
			if skip {
				return fs.SkipDir
			}
			return nil
		}
		if f := s.file(p, name, d); f != nil {
			out = append(out, *f)
		}
		return nil
	})
	if err != nil && ctx.Err() == nil {
		s.warn("walking %s: %v", s.web, err)
	}
	return out
}

// dir reports a directory worth a finding, and whether to skip its contents.
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

// file reports a file worth a finding.
func (s *scan) file(p, name string, d fs.DirEntry) *engine.Finding {
	lower := strings.ToLower(name)
	// Plugins and themes ship their own archives, examples and tests.
	inComponent := strings.Contains(filepath.ToSlash(p), "/wp-content/plugins/") || strings.Contains(filepath.ToSlash(p), "/wp-content/themes/")
	size := int64(-1)
	if fi, err := d.Info(); err == nil {
		size = fi.Size()
	}
	ev := []string{s.rel(p) + sizeNote(size)}
	regular := d.Type().IsRegular()
	secrets := func() []matchers.Secret {
		if !regular {
			return nil
		}
		b, err := readHead(p, maxRead)
		if err != nil {
			return nil
		}
		return matchers.FindSecrets(b)
	}
	with := func(f engine.Finding, sec []matchers.Secret) *engine.Finding {
		f.Evidence.Secrets = sec
		return &f
	}

	switch {
	case envName.MatchString(name) && !slices.Contains(envTemplates, lower):
		sec := secrets()
		sev := engine.Medium
		if len(sec) > 0 {
			sev = engine.High
			ev = append(ev, fmt.Sprintf("%d secrets (masked below)", len(sec)))
		}
		return with(s.finding("local-dotenv", sev, p, name+" file in the web root", ev,
			"Environment files hold database passwords and API keys. Servers don't block them by default, so anyone could download it.",
			"Move it above the web root, or block dotfiles in the server config (nginx: location ~ /\\. { deny all; }). Rotate any secrets in it if it was ever reachable.",
			"leak", "secrets"), sec)

	case wpConfigCopy.MatchString(name) && lower != "wp-config.php" && lower != "wp-config-sample.php" && !strings.HasSuffix(lower, ".php"):
		sec := secrets()
		return with(s.finding("local-wp-config-backup", engine.High, p, "Copy of wp-config.php in the web root", ev,
			"The server sends this copy as plain text rather than running it, exposing the database password and keys.",
			"Delete it, then change the database password and keys if it was ever reachable.",
			"leak", "secrets", "wordpress"), sec)

	case phpCopy.MatchString(name):
		return with(s.finding("local-php-backup", engine.Medium, p, "Backup copy of a PHP file in the web root", ev,
			"The server sends backup copies as plain text, exposing source code and any credentials in it.",
			"Delete editor and backup copies from the server.", "leak", "source"), secrets())

	case sqlDump.MatchString(name) && !inComponent: // plugins ship schema files
		return s.findingPtr("local-sql-dump", engine.High, p, "Database dump in the web root", ev,
			"A database dump holds user accounts, password hashes, emails and orders. If served, anyone can download all of it.",
			"Move dumps off the server or above the web root, and delete old ones.", "leak", "database")

	case archive.MatchString(name) && !inComponent && (lower == "wp-content.zip" || strings.HasSuffix(lower, ".wpress") ||
		filepath.Dir(p) == s.web || siteish.MatchString(name) || strings.Contains(lower, strings.ToLower(filepath.Base(s.root)))):
		return s.findingPtr("local-backup-archive", engine.High, p, "Backup archive in the web root", ev,
			"Site backups usually contain the whole site including wp-config.php or .env. Backup plugins protect their folders with .htaccess, which nginx ignores.",
			"Store backups outside the web root or off the server, and delete old ones.", "leak", "backup")

	case lower == "debug.log" || lower == "error_log" || lower == "error.log" || lower == "php_errors.log" || lower == "php-errors.log":
		return with(s.finding("local-log-file", engine.Medium, p, "Log file in the web root", ev,
			"Error logs reveal file paths, plugin internals, and sometimes queries, emails or tokens.",
			"Write logs outside the web root (WP_DEBUG_LOG or error_log in php.ini) and delete this one.",
			"leak", "disclosure"), secrets())

	case strings.HasPrefix(lower, "adminer") && strings.HasSuffix(lower, ".php"):
		return s.findingPtr("local-db-admin", engine.Medium, p, "Adminer in the web root", ev,
			"A database login page on the public site invites password guessing, and old Adminer versions have known vulnerabilities.",
			"Delete it when you're done, or restrict it to your IP address.", "php", "database", "admin")

	case strings.HasSuffix(lower, ".php") && regular && size >= 0 && size <= maxPHPInfoSize && !inComponent &&
		(infoName.MatchString(name) || filepath.Dir(p) == s.web):
		if b, err := readHead(p, maxPHPInfoSize); err == nil && phpinfoFn.Match(b) {
			return s.findingPtr("local-phpinfo", engine.Medium, p, "phpinfo() page in the web root", ev,
				"phpinfo() shows the PHP version, modules, paths and environment variables, which may include secrets.",
				"Delete it.", "php", "disclosure")
		}

	case lower == "auth.json" && !inComponent:
		if sec := secrets(); len(sec) > 0 || strings.Contains(string(mustHead(p)), "github-oauth") {
			return with(s.finding("local-composer-auth", engine.High, p, "Composer auth.json in the web root", ev,
				"auth.json holds tokens for GitHub and private package repositories.",
				"Move it out of the web root (use COMPOSER_AUTH or ~/.composer/auth.json) and rotate the tokens.",
				"leak", "secrets"), sec)
		}

	case strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".key") || lower == "id_rsa" || lower == "id_ecdsa" || lower == "id_ed25519":
		if sec := secrets(); slices.ContainsFunc(sec, func(x matchers.Secret) bool { return x.Kind == "private-key" }) {
			return with(s.finding("local-private-key", engine.High, p, "Private key in the web root", ev,
				"Anyone who downloads a private key can impersonate the server or log in where the key is trusted.",
				"Move it out of the web root, and replace the key if it was ever reachable.", "leak", "secrets"), sec)
		}
	}
	return nil
}

func (s *scan) findingPtr(id string, sev engine.Severity, p, title string, ev []string, impact, fix string, tags ...string) *engine.Finding {
	f := s.finding(id, sev, p, title, ev, impact, fix, tags...)
	return &f
}

func mustHead(p string) []byte {
	b, _ := readHead(p, maxRead)
	return b
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
