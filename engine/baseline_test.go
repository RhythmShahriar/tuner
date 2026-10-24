// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/checks"
	"github.com/RhythmShahriar/tuner/matchers"
)

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

// shippedCheck loads one check from the shipped checks tree.
func shippedCheck(t *testing.T, id string) *Check {
	t.Helper()
	all, err := LoadChecks(checks.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range all {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no shipped check %q", id)
	return nil
}

// catchAll serves routes as given and body with status 200 for every
// other path, like a site that never sends a 404.
func catchAll(routes map[string]string, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := routes[r.URL.Path]; ok {
			w.Write([]byte(b))
			return
		}
		w.Write([]byte(body))
	}))
}

func scanFindings(t *testing.T, srv *httptest.Server, cs ...*Check) []Finding {
	t.Helper()
	res, err := New(cs, Options{HTTPClient: srv.Client()}).Scan(context.Background(), srv.URL, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	return res.Findings
}

func TestSoftFourOhFourKeepsContentProvenLeak(t *testing.T) {
	env := "APP_NAME=shop\nAPP_ENV=production\nDB_HOST=127.0.0.1\nDB_PASSWORD=hunter22hunter\n"
	page := "<html><title>Not found</title><body>Nothing here, go back home!!!</body></html>\n"
	if len(env) != 78 || len(page) != 80 {
		t.Fatalf("fixture sizes %d and %d, want 78 and 80", len(env), len(page))
	}
	srv := catchAll(map[string]string{"/.env": env}, page)
	defer srv.Close()
	got := scanFindings(t, srv, shippedCheck(t, "leak-dotenv"))
	if len(got) != 1 || got[0].Path != "/.env" {
		t.Errorf("findings %+v, want leak-dotenv on /.env", got)
	}
}

func TestSoftFourOhFourFiltersEnvLikeCatchAll(t *testing.T) {
	srv := catchAll(nil, "FOO=bar\nBAZ=qux\n")
	defer srv.Close()
	if got := scanFindings(t, srv, shippedCheck(t, "leak-dotenv")); len(got) != 0 {
		t.Errorf("catch-all with env-like lines: findings %+v", got)
	}
}

// A pattern that names the path ("Index of /backup/") can't prove a page
// that echoes every path it is asked for; the page minus the path is the
// same as the probe's, so it is filtered. A real listing next to that
// catch-all is still reported.
func TestSoftFourOhFourFiltersPathEchoCatchAll(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><head><title>Index of " + r.URL.Path + "</title></head></html>"))
	}))
	defer echo.Close()
	if got := scanFindings(t, echo, shippedCheck(t, "leak-staging-listing")); len(got) != 0 {
		t.Errorf("path-echo catch-all: findings %+v", got)
	}

	listing := "<html><head><title>Index of /old/</title></head><body><pre><a href=\"../\">../</a>\n<a href=\"wp-config.php\">wp-config.php</a></pre></body></html>"
	srv := catchAll(map[string]string{"/old/": listing}, "<html><head><title>Index of /</title></head></html>")
	defer srv.Close()
	if got := scanFindings(t, srv, shippedCheck(t, "leak-staging-listing")); len(got) != 1 || got[0].Path != "/old/" {
		t.Errorf("real listing: findings %+v", got)
	}
}

func TestSoftFourOhFourHugeCatchAll(t *testing.T) {
	statusOnly := mustParse(t, `
id: t-status
name: status only
severity: medium
request: {path: ["/backup/", "/huge.bin"]}
match: {all: [{status: 200}, {not_baseline: true}]}
`)
	page := strings.Repeat("<p>catch-all filler</p>\n", 100_000) // over 2 MiB
	srv := catchAll(nil, page)
	defer srv.Close()
	if got := scanFindings(t, srv, statusOnly, shippedCheck(t, "leak-dotenv")); len(got) != 0 {
		t.Errorf(">1 MiB catch-all: findings %+v", got)
	}

	// A different large file behind the same catch-all is still a hit,
	// although both bodies are cut to the same length.
	srv2 := catchAll(map[string]string{"/huge.bin": strings.Repeat("\x00binary", 300_000)}, page)
	defer srv2.Close()
	if got := scanFindings(t, srv2, statusOnly); len(got) != 1 || got[0].Path != "/huge.bin" {
		t.Errorf("large real file: findings %+v, want one on /huge.bin", got)
	}
}

func TestSimilarCutBodies(t *testing.T) {
	a := &matchers.Response{Status: 200, Body: bytes.Repeat([]byte("a"), maxBody)}
	b := &matchers.Response{Status: 200, Body: bytes.Repeat([]byte("b"), maxBody)}
	if similar(a, "/x", b, "/y") {
		t.Error("cut bodies with different starts compared similar")
	}
	c := &matchers.Response{Status: 200, Body: append(bytes.Repeat([]byte("a"), headSize), bytes.Repeat([]byte("z"), maxBody-headSize)...)}
	if !similar(a, "/x", c, "/y") {
		t.Error("cut bodies with the same first 64 KiB compared different")
	}
}
