// Package fingerprint identifies the platform behind a site from its home page.
package fingerprint

import (
	"bytes"
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
	PHPSource string   `json:"php_source,omitempty"` // header and path the PHP version came from, e.g. "x-powered-by /wp-login.php"
	Server    string   `json:"server,omitempty"`

	Components []Component `json:"components,omitempty"`
}

// Component is a WordPress plugin or theme seen on the site.
type Component struct {
	Type    string `json:"type"` // plugin or theme
	Slug    string `json:"slug"`
	Version string `json:"version,omitempty"`
	Source  string `json:"version_source,omitempty"` // readme, style.css or asset
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
		parts = append(parts, strings.TrimSpace("PHP "+r.PHP))
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

	for _, c := range r.Header.Values("Set-Cookie") {
		switch {
		case strings.HasPrefix(c, "laravel_session="):
			add("laravel")
		case strings.HasPrefix(c, "PHPSESSID="):
			add("php")
		}
	}

	if v, build, header := PHPVersion(r.Header); v != "" {
		add("php")
		res.PHP, res.PHPBuild, res.PHPSource = v, build, header+" "+homePath(r)
	}
	if res.Has("wordpress") || res.Has("laravel") {
		add("php")
	}
	if s := r.Header.Get("Server"); s != "" {
		res.Server = matchers.Snippet([]byte(s))
	}
	return res
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
					build = m[1] + m[2]
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
