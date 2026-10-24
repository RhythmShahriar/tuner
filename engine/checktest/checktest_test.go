// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package checktest

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/RhythmShahriar/tuner/matchers"
)

// envCheck finds an exposed .env file with the given evidence regex.
func envCheck(regex string) string {
	return `id: fake-env
name: Fake env
severity: high
request:
  path: ["/.env"]
match:
  all:
    - status: 200
    - regex: '` + regex + `'
extract:
  secrets: true
`
}

const envFixture = `positive:
  - name: env
    expect_secrets: true
    routes:
      /.env:
        body: |
          DB_PWD=Hunter2-RealProdPassword
          DB_PASSWORD=supersecretvalue
negative:
  - name: blocked
    routes:
      /.env: {status: 403}
`

func fakeFS(check, fixture string) fstest.MapFS {
	return fstest.MapFS{
		"fake/env.yaml":      {Data: []byte(check)},
		"fake/env_test.yaml": {Data: []byte(fixture)},
	}
}

// The engine and the reports now hide what the leaky check matches, so
// the whole pipeline is clean in every format.
func TestLeakyCheckIsCleanInEveryFormat(t *testing.T) {
	// The whole first line is evidence and DB_PWD is no name the masking
	// rules knew before the shared secret rules.
	res := Run(fakeFS(envCheck(`(?m)^[A-Z_]+=.+`), envFixture))
	if len(res) != 2 {
		t.Fatalf("results = %+v", res)
	}
	for _, r := range res {
		if r.Failed(true) {
			t.Errorf("%s: problems %q, leaks %q", r, r.Problems, r.Leaks)
		}
	}
}

// The leak detector still finds a raw value in a report, so strict mode
// fails a check whose output shows one.
func TestLeakDetector(t *testing.T) {
	raw := rawValues([]byte("DB_PWD=Hunter2-RealProdPassword\n"), true)
	out := []byte(`{"matched": ["DB_PWD=Hunter2-RealProdPassword"]}`)
	got := leaks("json", out, raw, nil)
	want := `json output shows raw value "Hunter2-RealProdPassword"`
	if !slices.Contains(got, want) {
		t.Errorf("missing %q in %q", want, got)
	}
	r := Result{Leaks: got}
	if !r.Failed(true) || r.Failed(false) {
		t.Errorf("Failed(strict) = %v, Failed(lenient) = %v", r.Failed(true), r.Failed(false))
	}
	if got := leaks("json", out, raw, []byte("Hunter2-RealProdPassword")); len(got) != 0 {
		t.Errorf("a value in the check's own source counted: %q", got)
	}
}

func TestCleanCheckPasses(t *testing.T) {
	res := Run(fakeFS(envCheck(`(?m)^[A-Za-z_][A-Za-z0-9_]*=`), envFixture))
	for _, r := range res {
		if r.Failed(true) {
			t.Errorf("%s: problems %q, leaks %q", r, r.Problems, r.Leaks)
		}
	}
}

// A first line that clears the screen and retitles the window reaches no
// report. The detector names each control byte a report would hold.
func TestControlBytes(t *testing.T) {
	fixture := `positive:
  - name: escapes
    routes:
      /.env: {body: "X=\e]0;owned\a\e[2J\u009bclean\n"}
negative:
  - name: blocked
    routes:
      /.env: {status: 403}
`
	for _, r := range Run(fakeFS(envCheck(`(?m)^[A-Z_]+=.+`), fixture)) {
		if r.Failed(true) {
			t.Errorf("%s: problems %q, leaks %q", r, r.Problems, r.Leaks)
		}
	}
	found := strings.Join(leaks("plain", []byte("X=\x1b]0;owned\x07\x1b[2J\x9bclean"), nil, nil), "\n")
	for _, want := range []string{"ESC (0x1b)", "BEL (0x07)", "CSI (0x9b)"} {
		if !strings.Contains(found, want) {
			t.Errorf("missing %s in:\n%s", want, found)
		}
	}
}

func TestFixtureProblems(t *testing.T) {
	quiet := strings.Replace(envFixture, "status: 403", "status: 200, body: \"A=1\"", 1)
	for name, tc := range map[string]struct {
		fsys fstest.MapFS
		want string
	}{
		"missing fixture": {fstest.MapFS{"fake/env.yaml": {Data: []byte(envCheck(`x`))}}, "missing fixture fake/env_test.yaml"},
		"no negative":     {fakeFS(envCheck(`x`), "positive: [{name: a}]"), "needs at least one positive and one negative"},
		"unknown key":     {fakeFS(envCheck(`x`), "positive: [{name: a, bogus: 1}]"), "field bogus not found"},
		"no finding":      {fakeFS(envCheck(`NOPE`), envFixture), "no finding"},
		"false positive":  {fakeFS(envCheck(`(?m)^[A-Z_]+=`), quiet), "unexpected finding on /.env"},
		"bad check":       {fstest.MapFS{"fake/env.yaml": {Data: []byte("id: x")}}, "missing name"},
	} {
		t.Run(name, func(t *testing.T) {
			var all []string
			for _, r := range Run(tc.fsys) {
				all = append(all, r.Problems...)
			}
			if !strings.Contains(strings.Join(all, "\n"), tc.want) {
				t.Errorf("problems %q, want %q", all, tc.want)
			}
		})
	}
}

func TestHiddenParts(t *testing.T) {
	for _, tc := range []struct {
		body string
		want []string
	}{
		{"nothing here", nil},
		{"DB_PASSWORD=supersecretvalue\n", []string{"persecretvalue"}},
		{"a redis://u:S3cretRedisPass@host and AKIA1234567890ABCDEF end", []string{"cretRedisPass", "1234567890ABCDEF"}},
		{"TOKEN=abcdefghij", []string{"cdefghij"}},
	} {
		got := hiddenParts(tc.body, matchers.Redact(tc.body))
		if !slices.Equal(got, tc.want) {
			t.Errorf("hiddenParts(%q) = %q, want %q", tc.body, got, tc.want)
		}
	}
}

func TestWindows(t *testing.T) {
	if got := windows("short"); got != nil {
		t.Errorf("short value: %q", got)
	}
	if got := windows("abcdefghij"); !slices.Equal(got, []string{"abcdefgh", "bcdefghi", "cdefghij"}) {
		t.Errorf("windows = %q", got)
	}
}

// A secret cut short by truncation no longer matches its rule, so only
// part of it reaches a report. The window search still finds it.
func TestTruncatedSecretFound(t *testing.T) {
	raw := rawValues([]byte("GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"), false)
	out := []byte(`"matched": ["GITHUB_TOKEN=ghp_abcdefghijklmn"]`)
	if got := leaks("json", out, raw, nil); len(got) == 0 {
		t.Errorf("truncated secret not found among %q", raw)
	}
	// Words from the check itself are not leaks.
	if got := leaks("json", out, raw, out); len(got) != 0 {
		t.Errorf("source text reported: %q", got)
	}
}

func TestRawValuesInSecretFixtures(t *testing.T) {
	body := []byte("DB_PWD=Hunter2-RealProdPassword\nexport SMTP_PW='MailPass99'\nX=1\n" +
		`{"http-basic": {"repo": {"username": "u", "password": "s3cr3t-B4sic-Pass"}}}`)
	got := rawValues(body, true)
	for _, want := range []string{"Hunter2-RealProdPassword", "MailPass99", "s3cr3t-B4sic-Pass"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if slices.Contains(got, "1") || slices.Contains(got, "u") {
		t.Errorf("short values listed: %q", got)
	}
	if got := rawValues(body, false); slices.Contains(got, "Hunter2-RealProdPassword") {
		t.Errorf("key values listed outside a secret fixture: %q", got)
	}
}

func TestQueryRoutes(t *testing.T) {
	const check = `id: wp-thing
name: Users by route
severity: low
request:
  path: ["/?rest_route=/wp/v2/users"]
match:
  all:
    - status: 200
    - regex: '"slug"'
    - not_baseline: true
`
	// The query route answers its own query; every other query, the
	// baseline probe's too, gets the bare path's page.
	const fixture = `positive:
  - name: route answers
    routes:
      /: {body: home}
      /?rest_route=/wp/v2/users: {body: '[{"slug":"admin"}]'}
negative:
  - name: query ignored
    routes:
      /: {body: home}
`
	fsys := fstest.MapFS{"wp/thing.yaml": {Data: []byte(check)}, "wp/thing_test.yaml": {Data: []byte(fixture)}}
	for _, r := range Run(fsys) {
		if r.Failed(true) {
			t.Errorf("%s: problems %q", r, r.Problems)
		}
	}
}

// A fixture that redirects the home page to another host fails and no
// request reaches that host.
func TestFixtureStaysOnItsServer(t *testing.T) {
	var outside atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outside.Add(1)
		_, _ = w.Write([]byte("DB_PASSWORD=supersecretvalue\n"))
	}))
	defer other.Close()

	fixture := `positive:
  - name: redirected
    routes:
      /: {status: 302, headers: {Location: "` + other.URL + `/"}}
negative:
  - name: redirected
    routes:
      /: {status: 302, headers: {Location: "` + other.URL + `/"}}
`
	res := Run(fakeFS(envCheck(`(?m)^[A-Za-z_][A-Za-z0-9_]*=`), fixture))
	if len(res) != 2 {
		t.Fatalf("results = %+v", res)
	}
	// The engine stops at the cross-host redirect before the fixture's
	// dialer has to refuse it; either way the case fails.
	for _, r := range res {
		problems := strings.Join(r.Problems, "\n")
		if !r.Failed(false) || !strings.Contains(problems, "only the fixture server") && !strings.Contains(problems, "redirects to") {
			t.Errorf("%s: problems %q", r, r.Problems)
		}
	}
	if n := outside.Load(); n != 0 {
		t.Errorf("the other host got %d requests", n)
	}

	// The dialer refuses other addresses even without a redirect.
	srv, client, err := Case{}.server()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if resp, err := client.Get(other.URL); err == nil {
		_ = resp.Body.Close()
		t.Error("client reached another host")
	}
	resp, err := client.Get(srv.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if outside.Load() != 0 {
		t.Error("the other host got a request")
	}
}
