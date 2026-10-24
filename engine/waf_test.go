// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/matchers"
)

func responseFrom(h http.Header, status int, body string) *matchers.Response {
	return &matchers.Response{Status: status, Header: h, Body: []byte(body)}
}

// blockPage answers like each vendor's block or challenge page.
var blockPages = map[string]http.HandlerFunc{
	"cloudflare": func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Mitigated", "challenge")
		w.WriteHeader(403)
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=1"></script></body></html>`))
	},
	"sucuri": func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Sucuri-Block", "BL001")
		w.WriteHeader(403)
		w.Write([]byte(`<html><title>Sucuri WebSite Firewall - Access Denied</title></html>`))
	},
	"imperva": func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`<html><iframe src="/_Incapsula_Resource?CWUDNSAI=1&xinfo=2"></iframe></html>`))
	},
	"wordfence": func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
		w.Write([]byte(`<h1>Your access to this site has been limited by the site owner</h1>`))
	},
	"akamai": func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "AkamaiGHost")
		w.WriteHeader(403)
		w.Write([]byte(`<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY>Reference #18.6f2d3e17.1729760000.1a2b3c</BODY></HTML>`))
	},
}

var wafLabels = map[string]string{
	"cloudflare": "Cloudflare challenge", "sucuri": "Sucuri firewall", "imperva": "Imperva Incapsula",
	"wordfence": "Wordfence", "akamai": "Akamai",
}

func scanWith(t *testing.T, h http.Handler, checks ...*Check) (*Result, bool) {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	baseline := false
	res, err := New(checks, Options{HTTPClient: srv.Client()}).Scan(context.Background(), srv.URL, Hooks{
		Baseline: func(bool) { baseline = true },
	})
	if err != nil {
		t.Fatal(err)
	}
	return res, baseline
}

// Every path behind the block page: the scan runs but is partial. It
// never reports the block page's status as the site's 404 behavior.
func TestBlockedHomeMarksScanPartial(t *testing.T) {
	for id, h := range blockPages {
		t.Run(id, func(t *testing.T) {
			res, baseline := scanWith(t, h, mustParse(t, envCheck))
			want := "blocked by " + wafLabels[id] + ": results are partial; allow-list the scanner or pass -H/--cookie from an allowed session"
			if res.Complete || res.BlockedBy != id || res.StoppedBy != "waf" {
				t.Errorf("complete %v blocked_by %q stopped_by %q", res.Complete, res.BlockedBy, res.StoppedBy)
			}
			if len(res.Warnings) != 1 || res.Warnings[0] != want {
				t.Errorf("warnings %q, want %q", res.Warnings, want)
			}
			if baseline {
				t.Error("baseline reported behind a block page")
			}
			if b, _ := json.Marshal(res); !res.Soft404Unknown || !strings.Contains(string(b), `"soft_404_unknown":true`) {
				t.Errorf("soft-404 not marked unknown: %s", b)
			}
			if res.Checks != 1 || res.Requests < 2 {
				t.Errorf("scan did not continue: %d checks, %d requests", res.Checks, res.Requests)
			}
		})
	}
}

// The home page gets through but more than half the check paths hit a
// block page.
func TestBlockedChecksMarkScanPartial(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("<html>home</html>")) })
	mux.HandleFunc("/", blockPages["sucuri"])
	c := mustParse(t, `
id: t-many
name: many
severity: low
request: {path: ["/a", "/b", "/c"]}
match: {all: [{status: 200}]}
`)
	res, baseline := scanWith(t, mux, c)
	want := "blocked by Sucuri firewall on 3 of 3 check requests: results are partial; allow-list the scanner or pass -H/--cookie from an allowed session"
	if res.Complete || res.BlockedBy != "sucuri" || res.StoppedBy != "waf" || len(res.Warnings) != 1 || res.Warnings[0] != want {
		t.Errorf("complete %v blocked_by %q stopped_by %q warnings %q", res.Complete, res.BlockedBy, res.StoppedBy, res.Warnings)
	}
	if baseline {
		t.Error("baseline reported although the soft-404 probe hit a block page")
	}
	if !res.Soft404Unknown || res.Soft404 {
		t.Errorf("soft_404 %v unknown %v, want unknown", res.Soft404, res.Soft404Unknown)
	}
}

// Negatives: a plain 403 on one path and weak markers on normal pages
// leave the scan complete.
func TestNormalRefusalsStayComplete(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Iinfo", "10-123-0 NNNN CT(0 0 0) RT(1 2) q(0 0 0 -1) r(1 1) U5")
		w.Header().Add("Set-Cookie", "wfvt_123=abc; path=/")
		w.Write([]byte("<html><title>Just a moment</title>home</html>"))
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "Forbidden", http.StatusForbidden) })
	mux.HandleFunc("/", http.NotFound)
	res, baseline := scanWith(t, mux, mustParse(t, envCheck))
	if !res.Complete || res.BlockedBy != "" || res.StoppedBy != "" || len(res.Warnings) != 0 || !baseline {
		t.Errorf("complete %v blocked_by %q stopped_by %q warnings %q baseline %v", res.Complete, res.BlockedBy, res.StoppedBy, res.Warnings, baseline)
	}
	if b, _ := json.Marshal(res); res.Soft404Unknown || strings.Contains(string(b), "soft_404_unknown") {
		t.Errorf("soft-404 marked unknown on a normal site: %s", b)
	}
}

// Behind Incapsula or Wordfence the origin's own 403s carry the weak
// markers too. A hardened site that refuses every check path stays
// complete when its home page loads.
func TestWeakMarkersOnCheckRefusalsStayComplete(t *testing.T) {
	weak := func(w http.ResponseWriter) {
		w.Header().Set("X-Iinfo", "10-123-0 NNNN CT(0 0 0) RT(1 2) q(0 0 0 -1) r(1 1) U5")
		w.Header().Add("Set-Cookie", "wfvt_123=abc; path=/")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, _ *http.Request) { weak(w); w.Write([]byte("<html>home</html>")) })
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		weak(w)
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
	c := mustParse(t, `
id: t-many
name: many
severity: low
request: {path: ["/a", "/b", "/c"]}
match: {all: [{status: 200}]}
`)
	res, baseline := scanWith(t, mux, c)
	if !res.Complete || res.BlockedBy != "" || res.StoppedBy != "" || len(res.Warnings) != 0 || !baseline {
		t.Errorf("complete %v blocked_by %q stopped_by %q warnings %q baseline %v", res.Complete, res.BlockedBy, res.StoppedBy, res.Warnings, baseline)
	}
	// The same markers on a refused home page still mark it blocked.
	res, _ = scanWith(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		weak(w)
		http.Error(w, "Forbidden", http.StatusForbidden)
	}), c)
	if res.Complete || res.BlockedBy != "imperva" {
		t.Errorf("refused home: complete %v blocked_by %q", res.Complete, res.BlockedBy)
	}
}

func TestHomeStatusMarksScanPartial(t *testing.T) {
	res, baseline := scanWith(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}), mustParse(t, envCheck))
	want := "the home page answered 500: results are partial; check the URL, or pass -H/--cookie if the site needs a login"
	if res.Complete || res.StoppedBy != "home-status" || res.BlockedBy != "" || len(res.Warnings) != 1 || res.Warnings[0] != want {
		t.Errorf("complete %v stopped_by %q blocked_by %q warnings %q", res.Complete, res.StoppedBy, res.BlockedBy, res.Warnings)
	}
	if baseline {
		t.Error("baseline reported for a failing home page")
	}
}

// A check that would match the block page itself reports nothing.
func TestBlockPageIsNeverAFinding(t *testing.T) {
	c := mustParse(t, `
id: t-denied
name: denied
severity: low
request: {path: ["/x"]}
match: {all: [{status: 403}]}
`)
	res, _ := scanWith(t, blockPages["akamai"], c)
	if len(res.Findings) != 0 {
		t.Errorf("findings %+v", res.Findings)
	}
}

func TestDetectWAFWeakMarkersNeedARefusal(t *testing.T) {
	for status, want := range map[int]string{200: "", 404: "", 403: "imperva", 429: "imperva", 503: "imperva"} {
		resp := responseFrom(http.Header{"X-Iinfo": {"1"}}, status, "ok")
		got := ""
		if v := detectWAF(resp); v != nil {
			got = v.id
		}
		if got != want {
			t.Errorf("status %d: %q, want %q", status, got, want)
		}
	}
	wf := http.Header{"Set-Cookie": {"wfvt_42=abc; path=/"}}
	if v := detectWAF(responseFrom(wf, 403, "Forbidden")); v == nil || v.id != "wordfence" {
		t.Errorf("wfvt_ cookie on a 403: %v", v)
	}
	if detectWAF(responseFrom(wf, 200, "home")) != nil {
		t.Error("wfvt_ cookie on a normal page counted as a block")
	}
	if detectBlockPage(responseFrom(wf, 403, "Forbidden")) != nil || detectBlockPage(responseFrom(http.Header{"X-Iinfo": {"1"}}, 403, "no")) != nil {
		t.Error("weak markers counted on a check response")
	}
	if detectWAF(responseFrom(http.Header{"Server": {"AkamaiGHost"}}, 404, "not found")) != nil {
		t.Error("AkamaiGHost without a reference number counted as a block")
	}
	if !strings.Contains(blockedWarning(&wafVendors[0], ""), "Cloudflare challenge") {
		t.Error("label")
	}
}
