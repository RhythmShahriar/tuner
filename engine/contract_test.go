// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/fingerprint"
)

func TestConfidenceJSON(t *testing.T) {
	for _, c := range []Confidence{ConfidenceHigh, ConfidenceLow} {
		b, err := json.Marshal(Finding{ID: "x", Confidence: c})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"confidence":"`+string(c)+`"`) {
			t.Errorf("marshal %s: %s", c, b)
		}
		var back Finding
		if err := json.Unmarshal(b, &back); err != nil || back.Confidence != c {
			t.Errorf("round trip %s: got %q, %v", c, back.Confidence, err)
		}
	}
	if !ConfidenceHigh.Confirmed() || ConfidenceLow.Confirmed() || !Confidence("").Confirmed() {
		t.Error("Confirmed: want high and empty confirmed, low not")
	}
}

func TestSortFindings(t *testing.T) {
	fs := []Finding{
		{ID: "b", Severity: High, Confidence: ConfidenceLow},
		{ID: "c", Severity: Info},
		{ID: "a", Severity: High, Confidence: ConfidenceLow},
		{ID: "z", Severity: High, Confidence: ConfidenceHigh},
		{ID: "y", Severity: Critical},
	}
	SortFindings(fs)
	var got []string
	for _, f := range fs {
		got = append(got, f.ID)
	}
	if want := []string{"y", "z", "a", "b", "c"}; !slices.Equal(got, want) {
		t.Errorf("order %v, want %v", got, want)
	}
}

func TestFixServerAndComplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			_, _ = w.Write([]byte("SECRET=1"))
		}
	}))
	defer srv.Close()

	c := mustParse(t, envCheck+`fix_server:
  nginx: |
    location ~ /\.env { deny all; }
  apache: ""
`)
	res, err := New([]*Check{c}, Options{HTTPClient: srv.Client()}).Scan(context.Background(), srv.URL, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete || res.StoppedBy != "" {
		t.Errorf("complete %v, stopped by %q", res.Complete, res.StoppedBy)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings %+v", res.Findings)
	}
	fixes := res.Findings[0].Fixes
	if len(fixes) != 1 || fixes["nginx"] != `location ~ /\.env { deny all; }` {
		t.Errorf("fixes %q", fixes)
	}
	b, _ := json.Marshal(res)
	if !strings.Contains(string(b), `"complete":true`) {
		t.Errorf("JSON lacks complete: %s", b)
	}

	// A check without fix_server leaves Fixes out of the JSON.
	res, err = New([]*Check{mustParse(t, envCheck)}, Options{HTTPClient: srv.Client()}).Scan(context.Background(), srv.URL, Hooks{})
	if err != nil || len(res.Findings) != 1 || res.Findings[0].Fixes != nil {
		t.Fatalf("no fix_server: %+v, %v", res.Findings, err)
	}
}

func TestCanceledScanIsIncomplete(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	res, err := New([]*Check{mustParse(t, envCheck)}, Options{HTTPClient: srv.Client()}).Scan(ctx, srv.URL, Hooks{
		Fingerprint: func(fingerprint.Result) { cancel() },
	})
	if err == nil || res == nil || res.Complete {
		t.Errorf("canceled scan: complete %v, err %v", res != nil && res.Complete, err)
	}
}

func TestRules(t *testing.T) {
	RegisterRules("test-b", Rule{ID: "zz-test-rule", Severity: Low})
	RegisterRules("test-a", Rule{ID: "aa-test-", Prefix: true, Tags: []string{"t"}})
	var ids []string
	for _, r := range Rules() {
		if strings.HasSuffix(r.ID, "-test-rule") || strings.HasPrefix(r.ID, "aa-test-") {
			ids = append(ids, r.ID)
		}
	}
	if want := []string{"aa-test-", "zz-test-rule"}; !slices.Equal(ids, want) {
		t.Errorf("rules %v, want %v", ids, want)
	}
}
