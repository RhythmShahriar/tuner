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
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(zr)
		f.Close()

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
