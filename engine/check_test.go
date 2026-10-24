// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/RhythmShahriar/tuner/checks"
)

func checkYAML(method, path string) string {
	y := "id: t\nname: T\nseverity: low\nrequest:\n"
	if method != "" {
		y += "  method: " + method + "\n"
	}
	return y + "  path: [\"" + path + "\"]\nmatch: {all: [{status: 200}]}\n"
}

func TestParseCheckMethods(t *testing.T) {
	for in, want := range map[string]string{"": "GET", "GET": "GET", "get": "GET", "HEAD": "HEAD", "head": "HEAD"} {
		c, err := ParseCheck([]byte(checkYAML(in, "/x")))
		if err != nil {
			t.Errorf("method %q: %v", in, err)
			continue
		}
		if c.Request.Method != want {
			t.Errorf("method %q = %q, want %q", in, c.Request.Method, want)
		}
	}
	for _, m := range []string{"POST", "DELETE", "PUT", "patch", "OPTIONS", "TRACE", "CONNECT"} {
		_, err := ParseCheck([]byte(checkYAML(m, "/x")))
		if err == nil || !strings.Contains(err.Error(), "only use GET or HEAD") {
			t.Errorf("method %q: err = %v, want refusal", m, err)
		}
	}
}

func TestParseCheckQuery(t *testing.T) {
	for _, p := range []string{"/?author=1", "/x?a=1&b=two", "/x?a=", "/x?path=a/b.txt", "/x"} {
		if _, err := ParseCheck([]byte(checkYAML("", p))); err != nil {
			t.Errorf("path %q: %v", p, err)
		}
	}
	for _, p := range []string{
		"/?id=1%27%20OR%20SLEEP(5)--",
		"/x?a=<script>",
		"/x?a=1;b",
		"/x?a=1 b",
		"/x?a='1'",
		"/x?a=(1)",
		"/x?flag",
		"/x?",
		"/x?a=1&",
		"/x?a=1?b=2",
	} {
		_, err := ParseCheck([]byte(checkYAML("", p)))
		if err == nil || !strings.Contains(err.Error(), "plain name=value pairs") {
			t.Errorf("path %q: err = %v, want refusal", p, err)
		}
	}
}

// A refused check fails the whole load with an error naming its file, so
// a --checks dir or a pack cannot smuggle in a write request.
func TestLoadChecksNamesRefusedFile(t *testing.T) {
	fsys := fstest.MapFS{
		"ok.yaml":         {Data: []byte(strings.Replace(checkYAML("", "/x"), "id: t", "id: ok", 1))},
		"custom/del.yaml": {Data: []byte(checkYAML("DELETE", "/wp-json/wp/v2/posts/1?force=true"))},
	}
	_, err := LoadChecks(fsys)
	if err == nil || !strings.HasPrefix(err.Error(), "custom/del.yaml: request.method \"DELETE\"") {
		t.Errorf("err = %v", err)
	}
}

func TestBuiltinChecksOnlyRead(t *testing.T) {
	all, err := LoadChecks(checks.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range all {
		if c.Request.Method != "GET" && c.Request.Method != "HEAD" {
			t.Errorf("%s: method %s", c.File, c.Request.Method)
		}
	}
}
