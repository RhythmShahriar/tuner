// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// closedURL is an http:// address nothing listens on.
func closedURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "http://" + addr
}

// A password in a target URL goes out as an Authorization header and
// nowhere else: not in the live view's header, stderr or the JSON.
func TestTargetPasswordNeverShown(t *testing.T) {
	var auth atomic.Value
	auth.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.Header.Get("Authorization"); a != "" {
			auth.Store(a)
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	withPass := strings.Replace(srv.URL, "http://", "http://bob:pa55word@", 1)
	code, out, errs := tuner(t, "scan", withPass, "--plain", "--no-vulns")
	if code != exitOK || auth.Load() == "" {
		t.Fatalf("exit %d, auth %q: %s", code, auth.Load(), errs)
	}
	if strings.Contains(out+errs, "pa55word") {
		t.Errorf("password shown:\n%s%s", out, errs)
	}
	if !strings.Contains(out, "bob:xxxxx@") {
		t.Errorf("header lacks the masked target:\n%s", out)
	}

	down := strings.Replace(closedURL(t), "http://", "http://bob:pa55word@", 1)
	code, out, errs = tuner(t, "scan", down, "--json-array", "--no-vulns")
	if code != exitError || strings.Contains(out+errs, "pa55word") {
		t.Errorf("unreachable: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	var got []map[string]string
	if err := json.Unmarshal([]byte(out), &got); err != nil || len(got) != 1 {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(got[0]["target"], "bob:xxxxx@") {
		t.Errorf("target %q", got[0]["target"])
	}
	// The error field holds the reason; the hint is for stderr only.
	if e := got[0]["error"]; !strings.HasPrefix(e, "can't reach") || strings.ContainsAny(e, "\n�") || strings.Contains(e, "check the address") {
		t.Errorf("error %q", e)
	}
	if !strings.Contains(errs, "check the address and that the site is up") {
		t.Errorf("stderr lacks the hint: %s", errs)
	}

	// Without a scheme too.
	bare := strings.TrimPrefix(down, "http://")
	if _, out, errs := tuner(t, "scan", bare, "--json-array", "--no-vulns", "--timeout", "1s"); strings.Contains(out+errs, "pa55word") {
		t.Errorf("bare target: %s%s", out, errs)
	}
}

func TestShownTarget(t *testing.T) {
	for in, want := range map[string]string{
		"https://a:b@example.com/x": "https://a:xxxxx@example.com/x",
		"a:b@example.com":           "a:xxxxx@example.com",
		"example.com":               "example.com",
		"./site":                    "./site",
	} {
		if got := shownTarget(in); got != want {
			t.Errorf("shownTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

// A --proxy that does not parse is quoted without its credentials.
func TestBadProxyHidesPassword(t *testing.T) {
	code, _, errs := tuner(t, "scan", "example.com", "--proxy", "http//user:hunter2@p")
	if code != exitUsage || strings.Contains(errs, "hunter2") || strings.Contains(errs, "user") || !strings.Contains(errs, `bad --proxy "xxxxx@p"`) {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if got := redactProxy("socks5://u:p@[::1"); got != "socks5://xxxxx@[::1" {
		t.Errorf("redactProxy %q", got)
	}
}

// A missing --baseline file is a usage error, like a missing -l file.
func TestMissingBaselineIsUsage(t *testing.T) {
	code, _, errs := tuner(t, "scan", "example.com", "--baseline", "nope.json", "--no-config")
	if code != exitUsage || errs != "rhythm tuner scan: --baseline nope.json: no such file\n" {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
}

// A missing or unreadable --since file is a usage error too.
func TestBadSinceIsUsage(t *testing.T) {
	code, _, errs := tuner(t, "scan", "example.com", "--since", "nope.json", "--no-config")
	if code != exitUsage || errs != "rhythm tuner scan: --since nope.json: no such file\n" {
		t.Errorf("missing: exit %d, stderr %q", code, errs)
	}
	path := filepath.Join(t.TempDir(), "obj.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs = tuner(t, "scan", "example.com", "--since", path, "--no-config")
	if code != exitUsage || errs != "rhythm tuner scan: --since "+path+": not a Tuner JSON report: no rhythm-tuner schema\n" {
		t.Errorf("not a report: exit %d, stderr %q", code, errs)
	}
}

// A --baseline that isn't a Tuner JSON report, such as a SARIF file Tuner
// wrote, is a usage error rather than a baseline that hides nothing.
func TestNotReportBaselineIsUsage(t *testing.T) {
	dir := t.TempDir()
	for name, doc := range map[string]string{
		"out.sarif": `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[]}`,
		"obj.json":  `{}`,
		"arr.json":  `[]`,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		code, _, errs := tuner(t, "scan", "example.com", "--baseline", path, "--no-config")
		if code != exitUsage || !strings.HasPrefix(errs, "rhythm tuner scan: --baseline "+path+": not a Tuner JSON report") {
			t.Errorf("%s: exit %d, stderr %q", name, code, errs)
		}
	}
}

// A bare host and its http:// or https:// form are one site.
func TestDedupeBareHost(t *testing.T) {
	for _, c := range []struct{ in, want []string }{
		{[]string{"127.0.0.1:21100", "http://127.0.0.1:21100"}, []string{"http://127.0.0.1:21100"}},
		{[]string{"http://a.example/", "a.example", "http://b.example"}, []string{"http://a.example/", "http://b.example"}},
		{[]string{"a.example", "https://A.example"}, []string{"https://A.example"}},
		{[]string{"a.example", "b.example", "http://a.example:8080"}, []string{"a.example", "b.example", "http://a.example:8080"}},
		{[]string{"a.example", "a.example/"}, []string{"a.example"}},
	} {
		if got := dedupe(c.in); strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("dedupe(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	code, out, errs := tuner(t, "scan", strings.TrimPrefix(srv.URL, "http://"), srv.URL, "--json", "--no-vulns")
	if code != exitOK || strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Errorf("exit %d, want one report: %.200s %s", code, out, errs)
	}
}
