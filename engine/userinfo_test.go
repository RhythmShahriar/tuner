// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestURLUserinfoBecomesAuthorization(t *testing.T) {
	const pass = "Hunter2Pass"
	want := "Basic YWRtaW46SHVudGVyMlBhc3M=" // admin:Hunter2Pass
	srv := newLogServer(t, false, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			_, _ = w.Write([]byte("SECRET=1"))
		}
	})
	home := mustParse(t, `
id: t-home
name: home header
severity: low
request: {path: ["/"]}
match: {all: [{status: 200}, {missing_header: [X-Content-Type-Options]}]}
`)
	var logs []RequestLog
	s := New([]*Check{mustParse(t, envCheck), home}, Options{HTTPClient: srv.Client()})
	target := "http://admin:" + pass + "@" + srv.Listener.Addr().String()
	res, err := s.Scan(context.Background(), target, Hooks{Request: func(l RequestLog) { logs = append(logs, l) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings %+v", res.Findings)
	}
	out, _ := json.Marshal(res)
	if strings.Contains(string(out), pass) || strings.Contains(string(out), "admin@") {
		t.Errorf("result leaks the credentials: %s", out)
	}
	for _, l := range logs {
		if strings.Contains(l.URL, pass) || l.Err != nil && strings.Contains(l.Err.Error(), pass) {
			t.Errorf("request log leaks the password: %+v", l)
		}
	}
	reqs := srv.requests()
	if len(reqs) < 3 || len(reqs) != len(logs) {
		t.Errorf("%d requests, %d logged", len(reqs), len(logs))
	}
	for _, r := range reqs {
		if r.auth != want {
			t.Errorf("%s: Authorization %q, want %q", r.path, r.auth, want)
		}
	}

	// An explicit -H Authorization wins over the URL.
	h := http.Header{}
	h.Set("Authorization", "Bearer explicit")
	before := len(srv.requests())
	if _, err := New([]*Check{mustParse(t, envCheck)}, Options{Headers: h, HTTPClient: srv.Client()}).Scan(context.Background(), target, Hooks{}); err != nil {
		t.Fatal(err)
	}
	for _, r := range srv.requests()[before:] {
		if r.auth != "Bearer explicit" {
			t.Errorf("%s: Authorization %q with -H set", r.path, r.auth)
		}
	}

	// Unreachable targets don't echo the password in the error either.
	_, err = New(nil, Options{HTTPClient: srv.Client()}).Scan(context.Background(), "http://admin:"+pass+"@127.0.0.1:1", Hooks{})
	if err == nil || strings.Contains(err.Error(), pass) {
		t.Errorf("unreachable: %v", err)
	}
}

func TestParseTargetAuth(t *testing.T) {
	u, explicit, auth, err := ParseTargetAuth("https://user:p%40ss@example.com/blog")
	if err != nil || !explicit || u.User != nil || u.String() != "https://example.com/blog" || auth != "Basic dXNlcjpwQHNz" {
		t.Errorf("got %v %v %q %v", u, explicit, auth, err)
	}
	u, _, auth, _ = ParseTargetAuth("example.com")
	if auth != "" || u.String() != "https://example.com" {
		t.Errorf("no userinfo: %v %q", u, auth)
	}
	if u, _, _ := ParseTarget("http://a:b@example.com"); u.User != nil {
		t.Errorf("ParseTarget keeps userinfo: %v", u)
	}
	_, _, _, err = ParseTargetAuth("http://admin:Hunter2Pass@exa mple.com")
	if err == nil || strings.Contains(err.Error(), "Hunter2Pass") || !strings.Contains(err.Error(), "admin:xxxxx@") {
		t.Errorf("bad URL error: %v", err)
	}
	if got := RedactURL("https://u:pw@example.com/x"); got != "https://u:xxxxx@example.com/x" {
		t.Errorf("RedactURL = %q", got)
	}
	for raw, want := range map[string]string{
		"http://a:b@h/x?y=1@2": "http://a:xxxxx@h/x?y=1@2",
		"http://a@h":           "http://a@h",
		"http://h/p@q":         "http://h/p@q",
		"no scheme":            "no scheme",
	} {
		if got := redactUserinfo(raw); got != want {
			t.Errorf("redactUserinfo(%q) = %q, want %q", raw, got, want)
		}
	}
}
