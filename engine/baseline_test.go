package engine

import "testing"

func TestProbePath(t *testing.T) {
	cases := map[string]string{
		"/.env":                 "/.TOKEN",
		"/.env.local":           "/.TOKEN.local",
		"/wp-config.php.bak":    "/TOKEN.bak",
		"/wp-content/debug.log": "/wp-content/TOKEN.log",
		"/wp-content/uploads/":  "/wp-content/uploads/TOKEN/",
		"/.git/HEAD":            "/.git/TOKEN",
		"/xmlrpc.php":           "/TOKEN.php",
	}
	for in, want := range cases {
		if got := probePath(in, "TOKEN"); got != want {
			t.Errorf("probePath(%q) = %q, want %q", in, got, want)
		}
	}
}
