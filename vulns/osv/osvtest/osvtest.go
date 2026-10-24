// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package osvtest is a fake OSV.dev API for tests. It knows a few
// Packagist packages: laravel/framework 8.0.0 (two advisories),
// guzzlehttp/guzzle 7.4.1 (three) and acme/abandoned (one, never fixed).
// Every other package is clean.
package osvtest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Records are shaped like api.osv.dev's /v1/vulns answers.
var Records = map[string]string{
	"GHSA-aaaa": `{"id":"GHSA-aaaa","summary":"Query binding exploitation ","aliases":["CVE-2021-21263"],
		"affected":[{"package":{"ecosystem":"Packagist","name":"laravel/framework"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"6.20.11"},{"introduced":"7.0.0"},{"fixed":"7.30.2"},{"introduced":"8.0.0"},{"fixed":"8.22.1"}]}]}],
		"database_specific":{"severity":"HIGH"},
		"references":[{"type":"ADVISORY","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-21263"},{"type":"PACKAGE","url":"https://github.com/laravel/framework"}]}`,
	"GHSA-bbbb": `{"id":"GHSA-bbbb","summary":"Cookie issue","affected":[{"package":{"ecosystem":"Packagist","name":"laravel/framework"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"v8.40.0"}]}]}],
		"database_specific":{"severity":"MODERATE"}}`,
	"GHSA-cccc": `{"id":"GHSA-cccc","summary":"Unfixed","affected":[{"package":{"ecosystem":"Packagist","name":"acme/abandoned"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`,
	"GHSA-dddd": `{"id":"GHSA-dddd","summary":"Cross-domain cookie leakage","aliases":["CVE-2022-29248"],
		"affected":[{"package":{"ecosystem":"Packagist","name":"guzzlehttp/guzzle"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"7.0.0"},{"fixed":"7.4.3"}]}]}],
		"database_specific":{"severity":"HIGH"}}`,
	"GHSA-eeee": `{"id":"GHSA-eeee","summary":"Failure to strip the Cookie header on change in host or HTTP downgrade","aliases":["CVE-2022-31042"],
		"affected":[{"package":{"ecosystem":"Packagist","name":"guzzlehttp/guzzle"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"7.0.0"},{"fixed":"7.4.4"}]}]}],
		"database_specific":{"severity":"HIGH"}}`,
	"GHSA-ffff": `{"id":"GHSA-ffff","summary":"Change in port should be considered a change in origin","aliases":["CVE-2022-31091"],
		"affected":[{"package":{"ecosystem":"Packagist","name":"guzzlehttp/guzzle"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"7.0.0"},{"fixed":"7.4.5"}]}]}],
		"database_specific":{"severity":"HIGH"}}`,
}

// affected lists the advisories per "name@version"; a name alone matches
// every version.
var affected = map[string]string{
	"laravel/framework@8.0.0": `{"vulns":[{"id":"GHSA-aaaa","modified":"2024-01-01T00:00:00Z"},{"id":"GHSA-bbbb"}]}`,
	"guzzlehttp/guzzle@7.4.1": `{"vulns":[{"id":"GHSA-dddd"},{"id":"GHSA-eeee"},{"id":"GHSA-ffff"}]}`,
	"acme/abandoned":          `{"vulns":[{"id":"GHSA-cccc"}]}`,
}

// Server is the fake API. Hits counts requests; while Down is set every
// request gets a 502.
type Server struct {
	*httptest.Server
	Hits atomic.Int32
	Down atomic.Bool
}

// NewServer starts a fake OSV.dev API, closed when the test ends.
func NewServer(t testing.TB) *Server {
	f := &Server{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.Hits.Add(1)
		if f.Down.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct{ Name, Ecosystem string }
					Version string
				}
			}
			b, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(b, &req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			var results []string
			for _, q := range req.Queries {
				res, ok := affected[q.Package.Name+"@"+q.Version]
				if !ok {
					res, ok = affected[q.Package.Name]
				}
				if !ok || q.Package.Ecosystem != "Packagist" {
					res = `{}`
				}
				results = append(results, res)
			}
			_, _ = w.Write([]byte(`{"results":[` + strings.Join(results, ",") + `]}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			body, ok := Records[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	return f
}
