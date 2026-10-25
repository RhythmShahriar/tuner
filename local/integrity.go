// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
)

// Integrity checks compare WordPress core and wordpress.org plugin files
// with the checksums WordPress.org publishes for each release, the way
// `wp core verify-checksums` does, without running any PHP. A changed
// core file is the most common sign of a hacked site.

// Default checksum services.
const (
	DefaultWPOrgAPI = "https://api.wordpress.org"       // core checksums (MD5)
	DefaultWPDLAPI  = "https://downloads.wordpress.org" // plugin checksums (SHA-256)
)

// integrityChecks are the integrity check IDs, for the summary's count.
var integrityChecks = []string{
	"local-integrity-core-modified", "local-integrity-core-unknown", "local-integrity-core-missing",
	"local-integrity-plugin-modified", "local-integrity-plugin-unknown", "local-integrity-plugin-unchecked",
	"local-integrity-plugin-unlisted",
}

// Missing core files listed in one finding's evidence.
const maxMissingListed = 20

// Checksums fetches WordPress.org checksums. A release's checksums never
// change, so they are cached on disk for good; "this plugin isn't on
// wordpress.org" answers are kept for a day. Offline uses the cache only.
type Checksums struct {
	HTTP       *http.Client // nil means a client with a 20s timeout
	UserAgent  string       // sent with every request
	CoreBase   string       // default DefaultWPOrgAPI; a mirror for tests or air-gapped hosts
	PluginBase string       // default DefaultWPDLAPI
	CacheDir   string       // "" disables the disk cache
	Offline    bool         // never fetch; use cached checksums only

	once sync.Once
}

// errNotListed is a plugin or release WordPress.org has no checksums for.
var errNotListed = errors.New("not on wordpress.org")

// errNotCached is an offline lookup with nothing cached.
var errNotCached = errors.New("not cached")

// How long a "not listed" answer is trusted.
const notListedTTL = 24 * time.Hour

// init fills the defaults on first use, so Checksums needs no constructor.
func (c *Checksums) init() {
	c.once.Do(func() {
		if c.HTTP == nil {
			c.HTTP = &http.Client{Timeout: 20 * time.Second}
		}
		c.CoreBase = strings.TrimSuffix(cmp.Or(c.CoreBase, DefaultWPOrgAPI), "/")
		c.PluginBase = strings.TrimSuffix(cmp.Or(c.PluginBase, DefaultWPDLAPI), "/")
	})
}

// sumEntry is a cached answer.
type sumEntry struct {
	Fetched time.Time           `json:"fetched"`           // the TTL of a "not listed" answer counts from here
	Missing bool                `json:"missing,omitempty"` // wordpress.org has no checksums for it
	Files   map[string][]string `json:"files,omitempty"`   // path -> accepted hex hashes
}

// Core returns the MD5 of every file in a WordPress release, by path
// relative to the install.
func (c *Checksums) Core(ctx context.Context, version, locale string) (map[string][]string, error) {
	c.init()
	q := url.Values{"version": {version}, "locale": {locale}}
	return c.lookup(ctx, "core", version+"@"+locale, c.CoreBase+"/core/checksums/1.0/?"+q.Encode(), func(b []byte) (map[string][]string, error) {
		var r struct {
			Checksums json.RawMessage `json:"checksums"`
		}
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		// false for an unknown release or locale; a flat map when both
		// were given; keyed by version when the API ignored the locale.
		var flat map[string]string
		if json.Unmarshal(r.Checksums, &flat) != nil {
			var byVersion map[string]map[string]string
			if json.Unmarshal(r.Checksums, &byVersion) != nil || byVersion[version] == nil {
				return nil, errNotListed
			}
			flat = byVersion[version]
		}
		if len(flat) == 0 {
			return nil, errNotListed
		}
		out := make(map[string][]string, len(flat))
		for p, sum := range flat {
			out[p] = []string{strings.ToLower(sum)}
		}
		return out, nil
	})
}

// Plugin returns the SHA-256 of every file in a wordpress.org plugin
// release, by path relative to the plugin's folder.
func (c *Checksums) Plugin(ctx context.Context, slug, version string) (map[string][]string, error) {
	c.init()
	u := c.PluginBase + "/plugin-checksums/" + url.PathEscape(slug) + "/" + url.PathEscape(version) + ".json"
	return c.lookup(ctx, "plugin", slug+"@"+version, u, func(b []byte) (map[string][]string, error) {
		var r struct {
			Files map[string]struct {
				SHA256 json.RawMessage `json:"sha256"`
			} `json:"files"`
		}
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		if len(r.Files) == 0 {
			return nil, errNotListed
		}
		out := make(map[string][]string, len(r.Files))
		for p, f := range r.Files {
			// One hash, or several when the release was rebuilt.
			var one string
			var many []string
			switch {
			case json.Unmarshal(f.SHA256, &one) == nil:
				many = []string{one}
			case json.Unmarshal(f.SHA256, &many) == nil:
			default:
				continue
			}
			for i := range many {
				many[i] = strings.ToLower(many[i])
			}
			out[p] = many
		}
		return out, nil
	})
}

// hosted reports whether wordpress.org hosts the plugin slug at all, at
// any version. A plugin it hosts whose installed version has no
// checksums may have had its Version header edited to dodge the check.
func (c *Checksums) hosted(ctx context.Context, slug string) (bool, error) {
	c.init()
	q := url.Values{"action": {"plugin_information"}, "request[slug]": {slug}, "request[fields][sections]": {"0"}}
	_, err := c.lookup(ctx, "hosted", slug, c.CoreBase+"/plugins/info/1.2/?"+q.Encode(), func(b []byte) (map[string][]string, error) {
		var r struct {
			Slug string `json:"slug"`
		}
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		if r.Slug == "" {
			return nil, errNotListed
		}
		return map[string][]string{"slug": {r.Slug}}, nil
	})
	if errors.Is(err, errNotListed) {
		return false, nil
	}
	return err == nil, err
}

// lookup answers from the cache, or fetches u and parses it.
func (c *Checksums) lookup(ctx context.Context, kind, key, u string, parse func([]byte) (map[string][]string, error)) (map[string][]string, error) {
	path := c.path(kind, key)
	var e sumEntry
	if readSumCache(path, &e) {
		switch {
		case e.Files != nil:
			return e.Files, nil
		case e.Missing && (c.Offline || time.Since(e.Fetched) < notListedTTL):
			return nil, errNotListed
		}
	}
	if c.Offline {
		return nil, errNotCached
	}
	b, status, err := c.get(ctx, u)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		writeSumCache(path, sumEntry{Fetched: time.Now().UTC(), Missing: true})
		return nil, errNotListed
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", hostOf(u), status)
	}
	files, err := parse(b)
	switch {
	case errors.Is(err, errNotListed):
		writeSumCache(path, sumEntry{Fetched: time.Now().UTC(), Missing: true})
		return nil, err
	case err != nil:
		return nil, fmt.Errorf("%s: unexpected response: %w", hostOf(u), err)
	}
	writeSumCache(path, sumEntry{Fetched: time.Now().UTC(), Files: files})
	return files, nil
}

// get fetches u with the body capped at 32 MiB and returns it with the status.
func (c *Checksums) get(ctx context.Context, u string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return b, resp.StatusCode, err
}

// path is the cache file for key, or "" when there is no cache. The key
// comes from a version or plugin slug read on disk, so it is sanitized:
// a crafted slug must not write outside the cache directory.
func (c *Checksums) path(kind, key string) string {
	if c.CacheDir == "" {
		return ""
	}
	key = sumKeyChars.ReplaceAllString(strings.ReplaceAll(key, "/", "~"), "_")
	if key == "" || key == "." || key == ".." {
		return ""
	}
	return filepath.Join(c.CacheDir, kind, key+".json")
}

// Characters allowed in a cache file name; slugs and versions only need
// these; anything else could escape the cache folder.
var sumKeyChars = regexp.MustCompile(`[^A-Za-z0-9._@-]`)

// readSumCache loads a cached answer into e, reporting whether it could.
func readSumCache(path string, e *sumEntry) bool {
	if path == "" {
		return false
	}
	b, err := os.ReadFile(path) //nolint:gosec // path is built from the cache dir and a sanitized key
	return err == nil && json.Unmarshal(b, e) == nil
}

// writeSumCache writes atomically so a crash never leaves a torn file. A
// cache that can't be written is not an error: the next scan fetches
// again.
func writeSumCache(path string, e sumEntry) {
	if path == "" {
		return
	}
	b, err := json.Marshal(e)
	if err != nil || os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), path) != nil {
		_ = os.Remove(tmp.Name())
	}
}

// hostOf is u's host, for messages that name the service that failed.
func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil {
		return p.Host
	}
	return u
}

// integrityVisitor compares files with their checksums during the walk.
type integrityVisitor struct {
	s       *scan
	version string // WordPress version, for evidence
	locale  string
	core    map[string][]string            // core path -> MD5s
	plugins map[string]map[string][]string // slug -> path in plugin -> SHA-256s
	pver    map[string]string              // slug -> version
	collector
	mu   sync.Mutex
	seen map[string]bool // core paths the walk met
}

// prepareIntegrity fetches the checksums the walk needs, warning about
// anything it couldn't check. Checksums it couldn't load set
// s.integrityGap, which marks the scan partial. It returns nil when there is nothing to
// compare. Plugins wordpress.org doesn't host are no failure of the
// scan, so they get an info finding instead of a warning.
func (s *scan) prepareIntegrity(ctx context.Context) (*integrityVisitor, []engine.Finding) {
	if !s.opts.Integrity {
		return nil, nil
	}
	if s.wp == nil {
		s.warn("integrity: no WordPress install found, so no files were compared with checksums")
		return nil, nil
	}
	c := s.opts.Checksums
	if c == nil {
		c = &Checksums{}
	}
	v := &integrityVisitor{s: s, version: s.wp.version, locale: cmp.Or(s.wp.locale, "en_US"),
		plugins: map[string]map[string][]string{}, pver: map[string]string{}, seen: map[string]bool{}}

	if v.version == "" {
		s.warn("integrity: the WordPress version is unknown, so core files weren't compared with checksums")
	} else {
		core, err := c.Core(ctx, v.version, v.locale)
		switch {
		case err == nil:
			v.core = core
		case errors.Is(err, errNotCached):
			s.integrityGap = true
			s.warn("integrity: no cached checksums for WordPress %s (%s) while offline; run once online to cache them", v.version, v.locale)
		case errors.Is(err, errNotListed):
			s.warn("integrity: WordPress.org has no checksums for WordPress %s (%s), so core files weren't compared", v.version, v.locale)
		case ctx.Err() == nil:
			s.integrityGap = true
			s.warn("integrity: couldn't get checksums for WordPress %s (%s): %v", v.version, v.locale, err)
		}
	}

	// Plugins, a few at a time.
	var mu sync.Mutex
	var notListed, unlisted, noVersion, offline []string
	var failed []string
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, comp := range s.wp.components {
		if comp.Type != "plugin" {
			continue
		}
		if comp.Version == "" {
			noVersion = append(noVersion, comp.Slug)
			continue
		}
		if fi, err := os.Stat(filepath.Join(s.wp.content, "plugins", comp.Slug)); err != nil || !fi.IsDir() {
			continue // a single-file plugin such as hello.php
		}
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			sums, err := c.Plugin(ctx, comp.Slug, comp.Version)
			hosted := false
			if errors.Is(err, errNotListed) {
				// An error here (offline, say) leaves it a plugin that
				// isn't on wordpress.org, as before the lookup.
				hosted, _ = c.hosted(ctx, comp.Slug)
			}
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				v.plugins[comp.Slug], v.pver[comp.Slug] = sums, comp.Version
			case errors.Is(err, errNotListed) && hosted:
				unlisted = append(unlisted, comp.Slug+" "+comp.Version)
			case errors.Is(err, errNotListed):
				notListed = append(notListed, comp.Slug)
			case errors.Is(err, errNotCached):
				offline = append(offline, comp.Slug)
			case ctx.Err() == nil:
				failed = append(failed, comp.Slug+": "+err.Error())
			}
		})
	}
	wg.Wait()
	note := func(list []string, format string) {
		if len(list) > 0 {
			slices.Sort(list)
			s.warn(format, len(list), plural(len(list)), strings.Join(list, ", "))
		}
	}
	note(noVersion, "integrity: skipped %d plugin%s without a version: %s")
	note(offline, "integrity: skipped %d plugin%s with no cached checksums while offline: %s")
	note(failed, "integrity: couldn't get checksums for %d plugin%s: %s")
	// Checksums that should exist but couldn't be loaded leave files
	// unchecked, so the scan is partial, as with missing vulnerability
	// data. A plugin wordpress.org doesn't host is no gap.
	if len(failed) > 0 || len(offline) > 0 {
		s.integrityGap = true
	}
	var info []engine.Finding
	if len(notListed) > 0 {
		slices.Sort(notListed)
		f := s.finding("local-integrity-plugin-unchecked", engine.Info, filepath.Join(s.wp.content, "plugins"),
			fmt.Sprintf("%d plugin%s not on wordpress.org %s compared", len(notListed), plural(len(notListed)), plural2(len(notListed), "wasn't", "weren't")),
			[]string{"no checksums to compare: " + strings.Join(notListed, ", ")},
			"WordPress.org only publishes checksums for the plugins it hosts. Premium and custom plugins can't be checked this way, so a changed file in them goes unnoticed here.",
			"Compare them with a fresh copy from their vendor, or keep them in version control and check for changes there.",
			"integrity", "wordpress")
		f.Evidence.Request = "look up checksums"
		info = append(info, f)
	}
	if len(unlisted) > 0 {
		slices.Sort(unlisted)
		f := s.finding("local-integrity-plugin-unlisted", engine.Medium, filepath.Join(s.wp.content, "plugins"),
			fmt.Sprintf("%d wordpress.org plugin%s at a version wordpress.org never released", len(unlisted), plural(len(unlisted))),
			[]string{"no checksums for: " + strings.Join(unlisted, ", ")},
			"WordPress.org hosts these plugins but has no checksums for the installed version, so their files weren't compared. "+
				"A Version header edited to a release that doesn't exist hides changed files from this check.",
			"Check the version in each plugin's main file against its wordpress.org page. Reinstall the plugin from wordpress.org if it doesn't match.",
			"integrity", "wordpress", "malware")
		f.Confidence = engine.ConfidenceLow
		f.Caveat = "likely: a development build or a release published minutes ago has no checksums yet either"
		f.Evidence.Request = "look up checksums"
		info = append(info, f)
	}
	if v.core == nil && len(v.plugins) == 0 {
		return nil, info
	}
	return v, info
}

func (v *integrityVisitor) root() string { return v.s.wp.root }
func (v *integrityVisitor) checks() int  { return len(integrityChecks) }

// relPath is p relative to the install, with forward slashes.
func (v *integrityVisitor) relPath(p string) string {
	r, err := filepath.Rel(v.s.wp.root, p)
	if err != nil {
		return ""
	}
	return filepath.ToSlash(r)
}

// plugin splits a path inside wp-content/plugins/<slug>/ into the slug
// and the path within the plugin.
func (v *integrityVisitor) plugin(rel string) (slug, inner string, ok bool) {
	rest, ok := strings.CutPrefix(rel, "wp-content/plugins/")
	if !ok {
		return "", "", false
	}
	slug, inner, _ = strings.Cut(rest, "/")
	_, ok = v.plugins[slug]
	return slug, inner, ok
}

// enter keeps to wp-admin, wp-includes and the checked plugins' folders.
func (v *integrityVisitor) enter(e *entry) bool {
	rel := v.relPath(e.path)
	switch {
	case v.core != nil && (rel == "wp-admin" || rel == "wp-includes" ||
		strings.HasPrefix(rel, "wp-admin/") || strings.HasPrefix(rel, "wp-includes/")):
		return true
	case rel == "wp-content" || rel == "wp-content/plugins":
		return len(v.plugins) > 0
	}
	_, _, ok := v.plugin(rel)
	return ok
}

// need asks for the MD5 of every core file the release lists and of every
// listed plugin file. Unlisted PHP files in wp-admin and wp-includes are
// visited without hashing: their presence alone is the finding.
func (v *integrityVisitor) need(e *entry) need {
	rel := v.relPath(e.path)
	if _, ok := v.core[rel]; ok && !strings.HasPrefix(rel, "wp-content/") {
		if !e.regular() {
			return needVisit // a link: visit hashes its target
		}
		return needVisit | needMD5
	}
	isPHP := strings.HasSuffix(strings.ToLower(e.name), ".php")
	if v.core != nil && isPHP && (strings.HasPrefix(rel, "wp-admin/") || strings.HasPrefix(rel, "wp-includes/")) {
		return needVisit
	}
	if slug, inner, ok := v.plugin(rel); ok {
		if _, listed := v.plugins[slug][inner]; listed && e.regular() {
			return needVisit | needSHA256
		} else if listed || isPHP {
			return needVisit
		}
	}
	return 0
}

// visit compares one file with the checksums and reports a mismatch,
// a link in place of a core file or a file the release doesn't have.
func (v *integrityVisitor) visit(e *entry, f *fileData) {
	rel := v.relPath(e.path)
	ev := []string{v.s.rel(e.path) + sizeNote(f.size)}
	if sums, ok := v.core[rel]; ok && !strings.HasPrefix(rel, "wp-content/") {
		v.mu.Lock()
		v.seen[rel] = true
		v.mu.Unlock()
		if !e.regular() {
			lf, note := v.linkData(e, needMD5)
			ev = append(ev, note)
			if lf == nil {
				v.add(v.s.finding("local-integrity-core-modified", engine.High, e.path, "WordPress core file replaced by a link", ev,
					"WordPress ships this as a regular file. The link runs whatever it points to, which can't be compared with the release. Attackers use this to hide a changed core file; a few hosts link core to a shared copy on purpose.",
					"Check where the link points. If your host didn't set it up, replace it with the file from WordPress "+v.version+" (wp core download --force --skip-content --version="+v.version+").",
					"integrity", "wordpress", "malware"))
				return
			}
			f = lf
		}
		if f.md5 != "" && !slices.Contains(sums, f.md5) {
			ev = append(ev, fmt.Sprintf("MD5 %s, expected %s for WordPress %s (%s)", f.md5, sums[0], v.version, v.locale))
			v.add(v.s.finding("local-integrity-core-modified", engine.Critical, e.path, "Modified WordPress core file", ev,
				"Core files never change between updates. A changed one usually means the site was hacked and the file now runs the attacker's code, or someone patched core by hand.",
				"Compare it with a fresh copy of WordPress "+v.version+", then reinstall core (wp core download --force --skip-content --version="+v.version+"). Look for how the attacker got in before you clean up: other changed files, new admin users and old plugins.",
				"integrity", "wordpress", "malware"))
		}
		return
	}
	if slug, inner, ok := v.plugin(rel); ok {
		ver := v.pver[slug]
		if sums, listed := v.plugins[slug][inner]; listed {
			if !e.regular() {
				lf, note := v.linkData(e, needSHA256)
				ev = append(ev, note)
				if lf == nil {
					v.add(v.s.finding("local-integrity-plugin-modified", engine.High, e.path, "File in plugin "+slug+" replaced by a link", ev,
						"The wordpress.org release ships this as a regular file. The link runs whatever it points to, which can't be compared with the release.",
						"Check where the link points. If nobody set it up on purpose, reinstall the plugin (wp plugin install "+slug+" --force --version="+ver+").",
						"integrity", "wordpress", "malware"))
					return
				}
				f = lf
			}
			if f.sha256 != "" && !slices.Contains(sums, f.sha256) {
				ev = append(ev, fmt.Sprintf("SHA-256 %s, expected %s for %s %s", f.sha256, sums[0], slug, ver))
				v.add(v.s.finding("local-integrity-plugin-modified", engine.High, e.path, "Modified file in plugin "+slug, ev,
					"The file differs from the copy on wordpress.org for this version. Attackers hide backdoors in plugin files; a hand edit also gets lost on the next update.",
					"Reinstall the plugin from wordpress.org (wp plugin install "+slug+" --force --version="+ver+") after checking how the change got there.",
					"integrity", "wordpress", "malware"))
			}
			return
		}
		ev = append(ev, fmt.Sprintf("not part of %s %s on wordpress.org", slug, ver))
		v.add(v.s.finding("local-integrity-plugin-unknown", engine.Medium, e.path, "Unexpected PHP file in plugin "+slug, ev,
			"The wordpress.org release of this plugin has no such file. Attackers drop backdoors into plugin folders; some plugins also write their own cache or config files here.",
			"Check what the file does. If nobody added it on purpose, delete it and reinstall the plugin.",
			"integrity", "wordpress", "malware"))
		return
	}
	// A PHP file in wp-admin or wp-includes that no release has.
	ev = append(ev, fmt.Sprintf("not part of WordPress %s (%s)", v.version, v.locale))
	v.add(v.s.finding("local-integrity-core-unknown", engine.High, e.path, "Unexpected PHP file in WordPress core", ev,
		"WordPress never adds files to wp-admin or wp-includes outside an update, so an extra PHP file there is very likely a backdoor or left over from one.",
		"Check what the file does and when it appeared, then delete it and reinstall core (wp core download --force --skip-content --version="+v.version+").",
		"integrity", "wordpress", "malware"))
}

// linkData hashes what a link in place of a checked file points to. A
// link to a regular file inside the install is compared like the file
// itself, since some deploys link files within a release. For any other
// link it returns nil. The note says where the link points, for the
// evidence.
func (v *integrityVisitor) linkData(e *entry, n need) (*fileData, string) {
	shown, err := os.Readlink(e.path)
	if err != nil {
		shown = "an unreadable target"
	}
	shown = "a link to " + snippet([]byte(filepath.ToSlash(shown)), 0)
	target, err := filepath.EvalSymlinks(e.path)
	if err != nil {
		return nil, shown + " that doesn't resolve"
	}
	root, err := filepath.EvalSymlinks(v.s.wp.root)
	if err != nil {
		root = v.s.wp.root
	}
	if r, err := filepath.Rel(root, target); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return nil, shown + " outside the install, so it wasn't compared"
	}
	if fi, err := os.Stat(target); err != nil || !fi.Mode().IsRegular() {
		return nil, shown + ", which isn't a regular file"
	}
	return v.s.load(&entry{path: target, name: filepath.Base(target)}, n), shown
}

// done reports what the walk found, plus core files that are missing.
func (v *integrityVisitor) done() []engine.Finding {
	out := v.findings()
	if v.core == nil || v.s.stoppedBy != "" {
		return out // a stopped walk didn't see everything
	}
	var missing []string
	for rel := range v.core {
		if strings.HasPrefix(rel, "wp-content/") || v.seen[rel] {
			continue
		}
		// Double-check: the walk may have skipped an unreadable folder.
		if _, err := os.Lstat(filepath.Join(v.s.wp.root, filepath.FromSlash(rel))); errors.Is(err, os.ErrNotExist) {
			missing = append(missing, "/"+rel)
		}
	}
	if len(missing) == 0 {
		return out
	}
	slices.Sort(missing)
	ev := slices.Clone(missing[:min(len(missing), maxMissingListed)])
	if n := len(missing) - maxMissingListed; n > 0 {
		ev = append(ev, fmt.Sprintf("and %d more", n))
	}
	f := v.s.finding("local-integrity-core-missing", engine.Low, v.s.wp.root,
		fmt.Sprintf("%d WordPress core file%s missing", len(missing), plural(len(missing))), ev,
		"Files removed from core can break features or updates. Some hosts and hardening guides delete files such as readme.html or xmlrpc.php on purpose.",
		"If you didn't remove them on purpose, reinstall core (wp core download --force --skip-content --version="+v.version+").",
		"integrity", "wordpress")
	return append(out, f)
}
