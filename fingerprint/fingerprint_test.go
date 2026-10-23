package fingerprint

import (
	"net/http"
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

	// X-Powered-By wins over Server, and the home page records its source.
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
		{Type: "plugin", Slug: "contact-form-7", Version: "5.9.3", Source: "asset"},
		{Type: "plugin", Slug: "woocommerce"}, // ver equals the WordPress version, so it's ignored
		{Type: "theme", Slug: "astra", Version: "4.6.0", Source: "asset"},
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
