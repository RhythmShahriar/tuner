// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package fingerprint identifies the platform behind a site from its home page.
package fingerprint

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/RhythmShahriar/tuner/matchers"
)

// Result is what Tuner learned about the target.
type Result struct {
	Tech      []string `json:"tech"` // wordpress, laravel, php
	WordPress string   `json:"wordpress_version,omitempty"`
	PHP       string   `json:"php_version,omitempty"`
	PHPBuild  string   `json:"php_build,omitempty"`  // full build string when it carries a distro suffix, e.g. 7.4.3-4ubuntu2.19
	PHPSource string   `json:"php_source,omitempty"` // evidence for PHP: "<header> <path>" (e.g. "x-powered-by /wp-login.php"), cookie, probe, php on PATH, --php <path>; empty when only WordPress implies it
	Server    string   `json:"server,omitempty"`

	Components []Component `json:"components,omitempty"`
}

// Component is a WordPress plugin or theme seen on the site.
type Component struct {
	Type    string `json:"type"` // plugin or theme
	Slug    string `json:"slug"`
	Version string `json:"version,omitempty"`
	Source  string `json:"version_source,omitempty"` // readme, style.css or asset

	FoundBy    Methods `json:"found_by,omitempty"`   // how it was discovered: asset, rest, readme
	Confidence string  `json:"confidence,omitempty"` // high, or low when only a weak hint matched
}

// Methods is a set of discovery methods such as asset, rest and readme. It
// is a comma-separated string so Component stays comparable with ==; JSON
// shows it as an array.
type Methods string

// List returns the methods in the order they were added.
func (m Methods) List() []string {
	if m == "" {
		return nil
	}
	return strings.Split(string(m), ",")
}

// Has reports whether method is in the set.
func (m Methods) Has(method string) bool { return slices.Contains(m.List(), method) }

// With returns the set plus method.
func (m Methods) With(method string) Methods {
	switch {
	case method == "" || m.Has(method):
		return m
	case m == "":
		return Methods(method)
	}
	return m + "," + Methods(method)
}

// MarshalJSON writes the set as an array of strings.
func (m Methods) MarshalJSON() ([]byte, error) { return json.Marshal(m.List()) }

// UnmarshalJSON reads an array of strings.
func (m *Methods) UnmarshalJSON(b []byte) error {
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	*m = ""
	for _, s := range list {
		*m = m.With(s)
	}
	return nil
}

func (c Component) String() string {
	s := c.Slug
	if c.Type == "theme" {
		s = "theme " + s
	}
	if c.Version != "" {
		s += " " + c.Version
	}
	return s
}

// Has reports whether tech was detected.
func (r Result) Has(tech string) bool { return slices.Contains(r.Tech, tech) }

// String renders e.g. "WordPress 6.9.3 · PHP 8.1 · nginx".
func (r Result) String() string {
	var parts []string
	switch {
	case r.Has("wordpress"):
		parts = append(parts, strings.TrimSpace("WordPress "+r.WordPress))
	case r.Has("laravel"):
		parts = append(parts, "Laravel")
	}
	if r.Has("php") {
		if r.PHP == "" {
			parts = append(parts, "PHP (version unknown)")
		} else {
			parts = append(parts, "PHP "+r.PHP)
		}
	}
	if r.Server != "" {
		parts = append(parts, r.Server)
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, " · ")
}

var (
	wpGenerator = regexp.MustCompile(`<meta name="generator" content="WordPress ([0-9.]+)"`)
	wpBlockCSS  = regexp.MustCompile(`wp-includes/css/dist/block-library/[^"'?]*\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	phpPowered  = regexp.MustCompile(`PHP/([0-9][0-9.]*)([^\s,;]*)`)
	phpBare     = regexp.MustCompile(`(?i)(?:^|[\s,;])PHP(?:$|[\s,;/])`)
	wpAsset     = regexp.MustCompile(`/wp-content/(plugins|themes)/([A-Za-z0-9_-]+)/[^"'\s<>]*`)
	assetVer    = regexp.MustCompile(`(?:\?|&|&amp;|&#038;)ver=([0-9][0-9A-Za-z.-]*)`)
)

// Detect fingerprints the home page response.
func Detect(r *matchers.Response) Result {
	var res Result
	add := func(t string) {
		if !res.Has(t) {
			res.Tech = append(res.Tech, t)
		}
	}

	body := r.Body
	if m := wpGenerator.FindSubmatch(body); m != nil {
		add("wordpress")
		res.WordPress = string(m[1])
	} else if bytes.Contains(body, []byte("/wp-content/")) || bytes.Contains(body, []byte("/wp-includes/")) ||
		strings.Contains(r.Header.Get("Link"), "api.w.org") {
		add("wordpress")
		if m := wpBlockCSS.FindSubmatch(body); m != nil {
			res.WordPress = string(m[1])
		}
	}

	if res.Has("wordpress") {
		res.Components = components(body, res.WordPress)
	}

	// PHP is only claimed with evidence, strongest first: a PHP version
	// header, a bare "X-Powered-By: PHP", a PHP session cookie, or a .php
	// home page the server ran. WordPress alone adds PHP without a version
	// or source, shown as "PHP (version unknown)".
	if v, build, header := PHPVersion(r.Header); v != "" {
		add("php")
		res.PHP, res.PHPBuild, res.PHPSource = v, build, header+" "+homePath(r)
	} else if phpBare.MatchString(r.Header.Get("X-Powered-By")) {
		add("php")
		res.PHPSource = "x-powered-by " + homePath(r)
	}
	for _, c := range r.Header.Values("Set-Cookie") {
		switch {
		case strings.HasPrefix(c, "laravel_session="):
			add("laravel")
			res.setPHP("cookie")
		case PHPCookie(c):
			res.setPHP("cookie")
		}
	}
	if ExecutedPHP(r) {
		res.setPHP("probe")
	}
	if res.Has("wordpress") {
		add("php")
	}
	if s := r.Header.Get("Server"); s != "" {
		res.Server = matchers.Snippet([]byte(s)) // cleans control bytes too
	}
	return res
}

// setPHP records PHP as detected by source, unless a stronger source
// already did.
func (r *Result) setPHP(source string) {
	if !r.Has("php") {
		r.Tech = append(r.Tech, "php")
	}
	if r.PHPSource == "" {
		r.PHPSource = source
	}
}

// PHPCookie reports whether a Set-Cookie value starts PHP's default
// session cookie.
func PHPCookie(setCookie string) bool { return strings.HasPrefix(setCookie, "PHPSESSID=") }

// ExecutedPHP reports whether r is a .php URL the server ran rather than
// served as a file: a 2xx reply whose body is not PHP source. A static
// server hands back the source (or a 404), so it never counts.
func ExecutedPHP(r *matchers.Response) bool {
	if r.URL == nil || !strings.HasSuffix(strings.ToLower(r.URL.Path), ".php") || r.Status < 200 || r.Status > 299 {
		return false
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	return strings.HasPrefix(ct, "text/html") && !bytes.Contains(r.Body, []byte("<?php"))
}

func homePath(r *matchers.Response) string {
	if r.URL != nil && r.URL.Path != "" {
		return r.URL.Path
	}
	return "/"
}

// PHPVersion reads the PHP version from X-Powered-By, or from Server when
// it carries a PHP/x.y.z token as some Apache builds do. build is the full
// string when it has a distro suffix (7.4.3-4ubuntu2.19), else "". header
// names where it was found, in lower case.
func PHPVersion(h http.Header) (version, build, header string) {
	for _, name := range []string{"X-Powered-By", "Server"} {
		for _, v := range h.Values(name) {
			if m := phpPowered.FindStringSubmatch(v); m != nil {
				if m[2] != "" {
					build = matchers.CleanText(m[1] + m[2])
				}
				return m[1], build, strings.ToLower(name)
			}
		}
	}
	return "", "", ""
}

// components lists plugins and themes referenced by asset URLs. An asset's
// ?ver= is only a hint: many plugins pass the WordPress version instead of
// their own, so that value is ignored.
func components(body []byte, wpVersion string) []Component {
	var out []Component
	index := map[string]int{}
	for _, m := range wpAsset.FindAllSubmatch(body, -1) {
		typ := strings.TrimSuffix(string(m[1]), "s")
		key := typ + "/" + string(m[2])
		i, ok := index[key]
		if !ok {
			i = len(out)
			index[key] = i
			out = append(out, Component{Type: typ, Slug: string(m[2])})
		}
		if v := assetVer.FindSubmatch(m[0]); v != nil && out[i].Version == "" && string(v[1]) != wpVersion {
			out[i].Version, out[i].Source = string(v[1]), "asset"
		}
	}
	return out
}
