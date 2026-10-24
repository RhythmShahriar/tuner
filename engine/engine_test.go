// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mustParse(t *testing.T, y string) *Check {
	t.Helper()
	c, err := ParseCheck([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const envCheck = `
id: t-env
name: env
severity: critical
request: {path: ["/.env"]}
match: {all: [{status: 200}, {regex: "SECRET"}]}
`

func TestCustomHeadersAndUserAgent(t *testing.T) {
	var ua, cookie, host atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua.Store(r.UserAgent())
		cookie.Store(r.Header.Get("Cookie"))
		host.Store(r.Host)
	}))
	defer srv.Close()

	h := http.Header{}
	h.Set("Cookie", "session=abc")
	h.Set("Host", "staging.example.com")
	s := New([]*Check{mustParse(t, envCheck)}, Options{UserAgent: "custom-agent/1", Headers: h, HTTPClient: srv.Client()})
	if _, err := s.Scan(context.Background(), srv.URL, Hooks{}); err != nil {
		t.Fatal(err)
	}
	if ua.Load() != "custom-agent/1" || cookie.Load() != "session=abc" || host.Load() != "staging.example.com" {
		t.Errorf("got UA %q, Cookie %q, Host %q", ua.Load(), cookie.Load(), host.Load())
	}
}

func TestRetriesThrottledRequests(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" && hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if r.URL.Path == "/.env" {
			w.Write([]byte("SECRET=1"))
		}
	}))
	defer srv.Close()

	s := New([]*Check{mustParse(t, envCheck)}, Options{Retries: 2, HTTPClient: srv.Client()})
	res, err := s.Scan(context.Background(), srv.URL, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Throttled != 1 {
		t.Errorf("findings %d, throttled %d; want 1 and 1", len(res.Findings), res.Throttled)
	}
}

func TestRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c := mustParse(t, `
id: t-many
name: many
severity: low
request: {path: ["/a", "/b", "/c", "/d"]}
match: {all: [{status: 200}]}
`)
	start := time.Now()
	// 5 requests (home + 4 paths) at 20/s needs at least 200ms.
	if _, err := New([]*Check{c}, Options{Rate: 20, HTTPClient: srv.Client()}).Scan(context.Background(), srv.URL, Hooks{}); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 190*time.Millisecond {
		t.Errorf("5 requests at 20/s took %v", d)
	}
}

// Two targets on one host share the --rate pace when one Scanner scans
// both, as a batch or a long-running server does.
func TestRateSharedPerHost(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := mustParse(t, `
id: t-many
name: many
severity: low
request: {path: ["/a", "/b", "/c", "/d"]}
match: {all: [{status: 200}]}
`)
	s := New([]*Check{c}, Options{Rate: 20, HTTPClient: srv.Client()})
	start := time.Now()
	var wg sync.WaitGroup
	for _, target := range []string{srv.URL, srv.URL + "/blog"} {
		wg.Go(func() {
			if _, err := s.Scan(context.Background(), target, Hooks{}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	// At 20/s together, n requests need (n-1) * 50ms. Two separate paces
	// would finish in about half that.
	total := n.Load()
	if want := time.Duration(total-1) * 50 * time.Millisecond; time.Since(start) < want-20*time.Millisecond {
		t.Errorf("%d requests took %v, want at least %v", total, time.Since(start), want)
	}
	if s.paces.For("A.example") != s.paces.For("a.example") {
		t.Error("one host must get one pace")
	}
}

func TestSelect(t *testing.T) {
	all := []*Check{
		mustParse(t, "id: leak-a\nname: a\nseverity: critical\nprofile: quick\ntags: [leak]\nrequest: {path: [/a]}\nmatch: {all: [{status: 200}]}"),
		mustParse(t, "id: leak-b\nname: b\nseverity: low\ntags: [leak]\nrequest: {path: [/b]}\nmatch: {all: [{status: 200}]}"),
		mustParse(t, "id: hdr-c\nname: c\nseverity: medium\nprofile: deep\ntags: [headers]\nrequest: {path: [/]}\nmatch: {all: [{status: 200}]}"),
	}
	ids := func(s Selector) []string {
		got, err := Select(all, s)
		if err != nil {
			return []string{"error: " + err.Error()}
		}
		var out []string
		for _, c := range got {
			out = append(out, c.ID)
		}
		return out
	}
	cases := []struct {
		name string
		sel  Selector
		want []string
	}{
		{"default profile", Selector{}, []string{"leak-a", "leak-b"}},
		{"quick", Selector{Profile: ProfileQuick}, []string{"leak-a"}},
		{"deep", Selector{Profile: ProfileDeep}, []string{"leak-a", "leak-b", "hdr-c"}},
		{"tags", Selector{Profile: ProfileDeep, Tags: []string{"headers"}}, []string{"hdr-c"}},
		{"exclude tags", Selector{ExcludeTags: []string{"leak"}}, []string{"error: " + ErrNoChecks.Error()}},
		{"advisor ids only", Selector{IDs: []string{"vuln-*"}}, []string{"error: " + ErrNoChecks.Error()}},
		{"ids ignore profile", Selector{IDs: []string{"hdr-*"}}, []string{"hdr-c"}},
		{"exclude ids", Selector{ExcludeIDs: []string{"leak-a"}}, []string{"leak-b"}},
		{"min severity", Selector{MinSeverity: Medium, Profile: ProfileDeep}, []string{"leak-a", "hdr-c"}},
		{"unknown id", Selector{IDs: []string{"nope"}}, []string{"error: no check matches \"nope\"; list them with: rhythm tuner checks"}},
		{"typo gets a suggestion", Selector{IDs: []string{"leak-c"}}, []string{"error: no check matches \"leak-c\"; did you mean \"leak-a\"? list them with: rhythm tuner checks"}},
		{"swapped letters", Selector{IDs: []string{"hdr-c-"}}, []string{"error: no check matches \"hdr-c-\"; did you mean \"hdr-c\"? list them with: rhythm tuner checks"}},
		{"globs get no suggestion", Selector{IDs: []string{"lea-*"}}, []string{"error: no check matches \"lea-*\"; list them with: rhythm tuner checks"}},
		{"severity in any case", Selector{MinSeverity: "MEDIUM", Profile: "Deep"}, []string{"leak-a", "hdr-c"}},
		{"profile in any case", Selector{Profile: "QUICK"}, []string{"leak-a"}},
	}
	for _, tc := range cases {
		got := ids(tc.sel)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
				break
			}
		}
	}
}

func TestScore(t *testing.T) {
	fs := []Finding{
		{ID: "a", Severity: Critical, Path: "/x"},
		{ID: "a", Severity: Critical, Path: "/y"}, // same check twice counts once
		{ID: "b", Severity: High},
		{ID: "c", Severity: Info},
	}
	if got := Score(fs); got != 55 {
		t.Errorf("Score = %d, want 55", got)
	}
	if got := Score(nil); got != 100 {
		t.Errorf("clean Score = %d", got)
	}
	// Low-confidence findings count half (rounded up).
	if got := Score([]Finding{{ID: "vuln-apache", Severity: Critical, Confidence: "low"}}); got != 85 {
		t.Errorf("low-confidence Score = %d, want 85", got)
	}
	// A check with any confirmed finding counts in full.
	mixed := []Finding{{ID: "x", Severity: High, Confidence: "low"}, {ID: "x", Severity: High, Confidence: "high"}}
	if got := Score(mixed); got != 85 {
		t.Errorf("mixed-confidence Score = %d, want 85", got)
	}
}

func TestResolveVersions(t *testing.T) {
	routes := map[string]string{
		"/": `<link href="/wp-content/plugins/contact-form-7/a.css?ver=1.0">` +
			`<link href="/wp-content/themes/astra/style.css">`,
		"/feed/": `<generator>https://wordpress.org/?v=6.9.3</generator>`,
		"/wp-content/plugins/contact-form-7/readme.txt": "=== Contact Form 7 ===\nStable tag: 5.9.3\n",
		"/wp-content/themes/astra/style.css":            "/*\nTheme Name: Astra\nVersion: 4.6.0\n*/",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()

	res, err := New([]*Check{mustParse(t, envCheck)}, Options{HTTPClient: srv.Client()}).Scan(context.Background(), srv.URL, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	fp := res.Fingerprint
	if fp.WordPress != "6.9.3" || len(fp.Components) != 2 {
		t.Fatalf("got %+v", fp)
	}
	if c := fp.Components[0]; c.Version != "5.9.3" || c.Source != "readme" {
		t.Errorf("plugin = %+v", c)
	}
	if c := fp.Components[1]; c.Version != "4.6.0" || c.Source != "style.css" {
		t.Errorf("theme = %+v", c)
	}
}

func TestIsAdvisorID(t *testing.T) {
	for id, want := range map[string]bool{
		"vuln-*": true, "vuln-plugin-contact-form-7": true, "wp-components-outdated": true, "php-eol": true, "php-version-hidden": true,
		"wp-*": true, "leak-*": false, "*": false, "wp-xmlrpc": false, "hdr-csp-missing": false,
	} {
		if got := IsAdvisorID(id); got != want {
			t.Errorf("IsAdvisorID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestEvidenceHasNoControlBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Go's client rejects C0 bytes in headers but not C1 controls.
		w.Header().Set("Server", "nginx\u009b2J")
		if r.URL.Path == "/.env.local" {
			w.Write([]byte("APP_NAME=\x1b]52;c;ZWNobyBvd25lZA==\x07\nDB_PASSWORD=supersecret\n"))
		}
	}))
	defer srv.Close()
	c := mustParse(t, `
id: t-env-local
name: env
severity: critical
request: {path: ["/.env.local"]}
match: {all: [{status: 200}, {regex: "(?m)^[A-Z_]+=.+"}]}
extract: {secrets: true}
`)
	res, err := New([]*Check{c}, Options{HTTPClient: srv.Client()}).Scan(context.Background(), srv.URL, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings %+v", res.Findings)
	}
	for _, m := range res.Findings[0].Evidence.Matched {
		if strings.ContainsAny(m, "\x1b\x07") {
			t.Errorf("evidence keeps control bytes: %q", m)
		}
	}
	if strings.ContainsRune(res.Fingerprint.Server, 0x9b) {
		t.Errorf("server keeps control bytes: %q", res.Fingerprint.Server)
	}
}

func TestSuggestLeakDotenv(t *testing.T) {
	all := []*Check{
		mustParse(t, "id: leak-dotenv\nname: a\nseverity: critical\nrequest: {path: [/.env]}\nmatch: {all: [{status: 200}]}"),
		mustParse(t, "id: leak-git\nname: b\nseverity: high\nrequest: {path: [/.git/HEAD]}\nmatch: {all: [{status: 200}]}"),
	}
	_, err := Select(all, Selector{IDs: []string{"leak-dotnev"}})
	if err == nil || !strings.Contains(err.Error(), `did you mean "leak-dotenv"?`) {
		t.Errorf("err = %v", err)
	}
}

func TestParseSeverityAndProfile(t *testing.T) {
	if s, err := ParseSeverity("HIGH"); err != nil || s != High {
		t.Errorf("ParseSeverity(HIGH) = %q, %v", s, err)
	}
	if _, err := ParseSeverity("urgent"); err == nil || !strings.Contains(err.Error(), "want one of") {
		t.Errorf("ParseSeverity(urgent) err = %v", err)
	}
	if p, err := ParseProfile(" Quick "); err != nil || p != ProfileQuick {
		t.Errorf("ParseProfile(Quick) = %q, %v", p, err)
	}
	if _, err := ParseProfile("fast"); err == nil {
		t.Error("ParseProfile(fast) accepted")
	}
}

func TestEditDistance(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{{"", "", 0}, {"abc", "", 3}, {"leak-dotnev", "leak-dotenv", 2}, {"kitten", "sitting", 3}, {"same", "same", 0}} {
		if got := editDistance(tc.a, tc.b); got != tc.want {
			t.Errorf("editDistance(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
