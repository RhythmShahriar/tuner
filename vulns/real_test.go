// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real WPVulnerability responses (CC0), captured 2026-10-23. They carry
// the quirks fakes miss, such as "impact": [] for unscored advisories.
func TestDecodeRealResponses(t *testing.T) {
	files, _ := filepath.Glob("testdata/*.json.gz")
	if len(files) == 0 {
		t.Fatal("no testdata")
	}
	for _, path := range files {
		data, err := gunzip(path)
		if err != nil {
			t.Fatal(err)
		}

		var raw rawResponse
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		var d rawData
		if err := json.Unmarshal(raw.Data, &d); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		rec := d.normalize()
		if len(rec.Vulns) != len(d.Vulnerability) {
			t.Errorf("%s: decoded %d of %d advisories", path, len(rec.Vulns), len(d.Vulnerability))
		}
		for _, v := range rec.Vulns {
			if v.ID == "" || v.Title == "" || strings.Contains(v.Title, "  ") || strings.Contains(v.Title, "&#") ||
				(cveID.MatchString(v.Title) && v.Description != "") {
				t.Errorf("%s: bad advisory %+v", path, v)
				break
			}
		}
	}
}

func TestSummary(t *testing.T) {
	for in, want := range map[string]string{
		"[en] In PHP versions 8.2.* before 8.2.31, 8.3.* before 8.3.31, 8.4.* before 8.4.21, and 8.5.* before 8.5.6, the PDO Firebird driver improperly handles NUL bytes.": "The PDO Firebird driver improperly handles NUL bytes.",
		"In PHP version 8.0.* before 8.0.30,  8.1.* before 8.1.22, and 8.2.* before 8.2.8, when loading phar file, it overflows.":                                           "When loading phar file, it overflows.",
		"PHP uses longjmp() for out-of-memory errors.": "PHP uses longjmp() for out-of-memory errors.",
	} {
		if got := summary(langPrefix.ReplaceAllString(in, "")); got != want {
			t.Errorf("summary(%q) = %q, want %q", in, got, want)
		}
	}
}

func gunzip(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}
