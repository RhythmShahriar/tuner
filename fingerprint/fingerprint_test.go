// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package fingerprint

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/matchers"
)

func TestDetect(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx")
	h.Set("X-Powered-By", "PHP/8.1.2")
	r := &matchers.Response{Status: 200, Header: h, Body: []byte(`<meta name="generator" content="WordPress 6.9.3" />`)}
	got := Detect(r)
	if want := "WordPress 6.9.3 · PHP 8.1.2 · nginx"; got.String() != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	h = http.Header{}
	h.Add("Set-Cookie", "laravel_session=abc; path=/; httponly")
	got = Detect(&matchers.Response{Status: 200, Header: h, Body: []byte("<html></html>")})
	if !got.Has("laravel") || !got.Has("php") || got.Has("wordpress") {
		t.Errorf("laravel: got %+v", got)
	}

	if got := Detect(&matchers.Response{Status: 200, Header: http.Header{}, Body: []byte("hi")}); got.String() != "unknown" {
		t.Errorf("plain: got %q", got)
	}
}

func TestPHPVersion(t *testing.T) {
	cases := []struct {
		header, value         string
		version, build, where string
	}{
		{"X-Powered-By", "PHP/8.4.27", "8.4.27", "", "x-powered-by"},
		{"X-Powered-By", "PHP/7.4.3-4ubuntu2.19", "7.4.3", "7.4.3-4ubuntu2.19", "x-powered-by"},
		{"Server", "Apache/2.4.41 (Ubuntu) PHP/8.1.2-1ubuntu2.14 OpenSSL/3.0.2", "8.1.2", "8.1.2-1ubuntu2.14", "server"},
		{"Server", "Apache/2.4.62 (Unix) PHP/8.3.12", "8.3.12", "", "server"},
		{"Server", "nginx/1.25.3", "", "", ""},
		{"X-Powered-By", "Express", "", "", ""},
	}
	for _, tc := range cases {
		h := http.Header{}
		h.Set(tc.header, tc.value)
		v, build, where := PHPVersion(h)
		if v != tc.version || build != tc.build || where != tc.where {
			t.Errorf("%s: %s → %q %q %q", tc.header, tc.value, v, build, where)
		}
	}

	// X-Powered-By wins over Server; the home page records its source.
	h := http.Header{}
	h.Set("Server", "Apache PHP/7.4.33")
	h.Set("X-Powered-By", "PHP/8.2.1")
	got := Detect(&matchers.Response{Status: 200, Header: h, Body: []byte("x")})
	if got.PHP != "8.2.1" || got.PHPSource != "x-powered-by /" || !got.Has("php") {
		t.Errorf("got %+v", got)
	}
	h.Del("X-Powered-By")
	if got := Detect(&matchers.Response{Status: 200, Header: h, Body: []byte("x")}); got.PHP != "7.4.33" || got.PHPSource != "server /" {
		t.Errorf("Server only: got %+v", got)
	}
}

func TestComponents(t *testing.T) {
	body := []byte(`<meta name="generator" content="WordPress 6.9.3" />
<link href="/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.9.3">
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.9.3"></script>
<script src="https://cdn.example.com/wp-content/plugins/woocommerce/assets/js/x.js?ver=6.9.3"></script>
<link href='/wp-content/themes/astra/style.css?foo=1&#038;ver=4.6.0'>`)
	got := Detect(&matchers.Response{Status: 200, Header: http.Header{}, Body: body}).Components
	want := []Component{
		{Type: "plugin", Slug: "contact-form-7", Version: "5.9.3", Source: "asset", FoundBy: "asset", Confidence: "high"},
		{Type: "plugin", Slug: "woocommerce", FoundBy: "asset", Confidence: "high"}, // ver equals the WordPress version, so it's ignored
		{Type: "theme", Slug: "astra", Version: "4.6.0", Source: "asset", FoundBy: "asset", Confidence: "high"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("component %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestMethods(t *testing.T) {
	m := Methods("").With("asset").With("rest").With("asset").With("")
	if m != "asset,rest" || !m.Has("rest") || m.Has("readme") {
		t.Errorf("set %q", m)
	}
	b, err := json.Marshal(Component{Type: "plugin", Slug: "x", FoundBy: m})
	if err != nil || !strings.Contains(string(b), `"found_by":["asset","rest"]`) {
		t.Fatalf("marshal %s, %v", b, err)
	}
	var back Component
	if err := json.Unmarshal(b, &back); err != nil || back.FoundBy != m {
		t.Errorf("round trip %q, %v", back.FoundBy, err)
	}
	if b, _ := json.Marshal(Component{Slug: "y"}); strings.Contains(string(b), "found_by") {
		t.Errorf("empty set not omitted: %s", b)
	}
}

func TestPHPBuildCleaned(t *testing.T) {
	h := http.Header{}
	h.Set("X-Powered-By", "PHP/8.1.2-1ubuntu\x1b[2J")
	v, build, _ := PHPVersion(h)
	if v != "8.1.2" || strings.ContainsRune(build, 0x1b) || build != "8.1.2-1ubuntu�[2J" {
		t.Errorf("got %q %q", v, build)
	}
}

// PHP shows only with evidence. WordPress alone never brings a version.
func TestDetectPHPEvidence(t *testing.T) {
	home, _ := url.Parse("http://127.0.0.1/")
	php, _ := url.Parse("http://127.0.0.1/index.php")
	wp := []byte(`<meta name="generator" content="WordPress 6.9.3" />`)
	cases := []struct {
		name    string
		url     *url.URL
		header  http.Header
		body    []byte
		has     bool
		version string
		source  string
		str     string
	}{
		{"python static server", home, http.Header{"Server": {"SimpleHTTP/0.6 Python/3.12.3"}, "Content-Type": {"text/html"}}, []byte("<html>hi</html>"), false, "", "", "SimpleHTTP/0.6 Python/3.12.3"},
		{"express", home, http.Header{"X-Powered-By": {"Express"}}, []byte("x"), false, "", "", "unknown"},
		{"version header", home, http.Header{"X-Powered-By": {"PHP/8.2.1"}}, []byte("x"), true, "8.2.1", "x-powered-by /", "PHP 8.2.1"},
		{"bare header", home, http.Header{"X-Powered-By": {"PHP"}}, []byte("x"), true, "", "x-powered-by /", "PHP (version unknown)"},
		{"session cookie", home, http.Header{"Set-Cookie": {"PHPSESSID=abc; path=/"}}, []byte("x"), true, "", "cookie", "PHP (version unknown)"},
		{"laravel cookie", home, http.Header{"Set-Cookie": {"laravel_session=abc; path=/"}}, []byte("x"), true, "", "cookie", "Laravel · PHP (version unknown)"},
		{"executed php home", php, http.Header{"Content-Type": {"text/html; charset=UTF-8"}}, []byte("<html>shop</html>"), true, "", "probe", "PHP (version unknown)"},
		{"php source served as a file", php, http.Header{"Content-Type": {"text/html"}}, []byte("<?php echo 1;"), false, "", "", "unknown"},
		{"php file with a download type", php, http.Header{"Content-Type": {"application/x-httpd-php"}}, []byte("x"), false, "", "", "unknown"},
		{"wordpress without a php header", home, http.Header{}, wp, true, "", "", "WordPress 6.9.3 · PHP (version unknown)"},
		{"wordpress with a php header", home, http.Header{"X-Powered-By": {"PHP/8.1.2"}}, wp, true, "8.1.2", "x-powered-by /", "WordPress 6.9.3 · PHP 8.1.2"},
	}
	for _, c := range cases {
		got := Detect(&matchers.Response{URL: c.url, Status: 200, Header: c.header, Body: c.body})
		if got.Has("php") != c.has || got.PHP != c.version || got.PHPSource != c.source || got.String() != c.str {
			t.Errorf("%s: php %v %q source %q string %q, want %v %q %q %q", c.name, got.Has("php"), got.PHP, got.PHPSource, got.String(), c.has, c.version, c.source, c.str)
		}
	}
}
