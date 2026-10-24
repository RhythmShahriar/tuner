// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/fingerprint"
)

// A page cache strips X-Powered-By from the home page; uncacheable PHP
// endpoints still send it.
func TestProbePHP(t *testing.T) {
	cases := []struct {
		name    string
		home    func(http.ResponseWriter)
		headers map[string]http.Header // per path
		profile Profile
		php     string
		build   string
		source  string
		probed  []string // PHP endpoints requested, in order
	}{
		{
			name: "wordpress behind a cache",
			home: func(w http.ResponseWriter) { w.Write([]byte(`<link href="/wp-content/themes/astra/style.css">`)) },
			headers: map[string]http.Header{
				"/xmlrpc.php":              {}, // blocked at the edge, no PHP header
				"/wp-admin/admin-ajax.php": {"X-Powered-By": {"PHP/8.3.10"}},
				"/wp-login.php":            {"X-Powered-By": {"PHP/8.3.10"}},
			},
			php: "8.3.10", source: "x-powered-by /wp-admin/admin-ajax.php",
			probed: []string{"/xmlrpc.php", "/wp-admin/admin-ajax.php"},
		},
		{
			name:    "quick profile probes too, and reads Server",
			home:    func(w http.ResponseWriter) { w.Write([]byte(`<script src="/wp-includes/js/x.js"></script>`)) },
			headers: map[string]http.Header{"/xmlrpc.php": {"Server": {"Apache/2.4.41 (Ubuntu) PHP/7.4.3-4ubuntu2.19"}}},
			profile: ProfileQuick,
			php:     "7.4.3", build: "7.4.3-4ubuntu2.19", source: "server /xmlrpc.php",
			probed: []string{"/xmlrpc.php"},
		},
		{
			name: "laravel",
			home: func(w http.ResponseWriter) {
				w.Header().Add("Set-Cookie", "laravel_session=x; path=/")
				w.Write([]byte("<html></html>"))
			},
			headers: map[string]http.Header{"/index.php": {"X-Powered-By": {"PHP/8.4.1"}}},
			php:     "8.4.1", source: "x-powered-by /index.php",
			probed: []string{"/index.php"},
		},
		{
			name: "version on the home page: no probe",
			home: func(w http.ResponseWriter) {
				w.Header().Set("X-Powered-By", "PHP/8.2.1")
				w.Write([]byte(`<meta name="generator" content="WordPress 6.9.3" />`))
			},
			php: "8.2.1", source: "x-powered-by /",
		},
		{
			name: "not PHP: no probe",
			home: func(w http.ResponseWriter) { w.Write([]byte("<html>static</html>")) },
		},
		{
			name: "wordpress, PHP session cookie on a probe",
			home: func(w http.ResponseWriter) { w.Write([]byte(`<link href="/wp-content/plugins/x/y.css">`)) },
			headers: map[string]http.Header{
				"/wp-admin/admin-ajax.php": {"Set-Cookie": {"PHPSESSID=abc; path=/"}},
			},
			source: "probe",
			probed: []string{"/xmlrpc.php", "/wp-admin/admin-ajax.php", "/wp-login.php"},
		},
		{
			name:   "hidden everywhere",
			home:   func(w http.ResponseWriter) { w.Write([]byte(`<link href="/wp-content/plugins/x/y.css">`)) },
			probed: []string{"/xmlrpc.php", "/wp-admin/admin-ajax.php", "/wp-login.php"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var probed []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					tc.home(w)
					return
				}
				if slices.Contains(append(slices.Clone(wpPHPProbes), phpProbes...), r.URL.Path) {
					mu.Lock()
					probed = append(probed, r.URL.Path)
					mu.Unlock()
				}
				for k, v := range tc.headers[r.URL.Path] {
					w.Header()[k] = v
				}
				http.NotFound(w, r)
			}))
			defer srv.Close()

			res, err := New(nil, Options{HTTPClient: srv.Client(), Profile: tc.profile}).Scan(context.Background(), srv.URL, Hooks{})
			if err != nil {
				t.Fatal(err)
			}
			fp := res.Fingerprint
			if fp.PHP != tc.php || fp.PHPBuild != tc.build || fp.PHPSource != tc.source {
				t.Errorf("got PHP %q build %q source %q, want %q %q %q", fp.PHP, fp.PHPBuild, fp.PHPSource, tc.php, tc.build, tc.source)
			}
			if !slices.Equal(probed, tc.probed) {
				t.Errorf("probed %v, want %v", probed, tc.probed)
			}
		})
	}
}

type phpSpy struct{ fp fingerprint.Result }

func (s *phpSpy) Advise(_ context.Context, _ *url.URL, fp fingerprint.Result) ([]Finding, []string) {
	s.fp = fp
	return nil, nil
}

// A static server never shows PHP; a WordPress page with no PHP header
// shows PHP with no version, so the advisor cannot match PHP CVEs.
func TestRemotePHPNeedsEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		has        bool
		str        string
	}{
		{"static", "<html>static</html>", false, "unknown"},
		{"wordpress", `<meta name="generator" content="WordPress 6.4.3" />`, true, "WordPress 6.4.3 · PHP (version unknown)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					w.Write([]byte(tc.body))
					return
				}
				http.NotFound(w, r)
			}))
			defer srv.Close()
			spy := &phpSpy{}
			res, err := New(nil, Options{HTTPClient: srv.Client(), Advisor: spy}).Scan(context.Background(), srv.URL, Hooks{})
			if err != nil {
				t.Fatal(err)
			}
			fp := res.Fingerprint
			if fp.Has("php") != tc.has || fp.PHP != "" || fp.PHPSource != "" || fp.String() != tc.str {
				t.Errorf("fingerprint %+v, string %q", fp, fp.String())
			}
			if spy.fp.PHP != "" {
				t.Errorf("advisor saw PHP %q", spy.fp.PHP)
			}
		})
	}
}

func TestConcurrencyCapsEveryRequest(t *testing.T) {
	var home strings.Builder
	for i := range 50 {
		fmt.Fprintf(&home, `<link href="/wp-content/plugins/plugin-%d/a.css?ver=1.0">`, i)
	}
	var now, peak, total atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := now.Add(1)
		defer now.Add(-1)
		total.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		if r.URL.Path == "/" {
			w.Write([]byte(home.String()))
			return
		}
		time.Sleep(50 * time.Millisecond)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := mustParse(t, `
id: t-many
name: many
severity: low
request: {path: ["/a", "/b", "/c", "/d", "/e", "/f"]}
match: {all: [{status: 200}, {not_baseline: true}]}
`)
	for _, limit := range []int32{1, 4} {
		peak.Store(0)
		total.Store(0)
		_, err := New([]*Check{c}, Options{Concurrency: int(limit), HTTPClient: srv.Client()}).Scan(context.Background(), srv.URL, Hooks{})
		if err != nil {
			t.Fatal(err)
		}
		if total.Load() < 50 {
			t.Fatalf("-c %d: only %d requests, want the 50 readme lookups", limit, total.Load())
		}
		if p := peak.Load(); p > limit {
			t.Errorf("-c %d: %d requests in flight", limit, p)
		}
	}
}
