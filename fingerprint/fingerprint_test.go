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
