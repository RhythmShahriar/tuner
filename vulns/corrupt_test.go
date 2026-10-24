// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/fingerprint"
)

// badEntries are cache files a scan must survive: hand-edited, truncated
// to null, missing the {fetched, data} wrapper, or written by a Tuner
// from before cache entries carried a format.
var badEntries = map[string]string{
	"null-entry":   `null`,
	"empty-entry":  `{}`,
	"bare-record":  `{"name":"Gallery","vulns":[]}`,
	"format-0":     `{"fetched":"2026-10-22T00:00:00Z","data":{"name":"Old","vulns":[{"id":"x","title":"OLD TITLE"}]}}`,
	"null-data":    `{"format":1,"fetched":"2026-10-22T00:00:00Z","data":null}`,
	"no-fetched":   `{"format":1,"data":{"name":"Y","vulns":[]}}`,
	"broken-json!": `{"format":1,`,
}

func seedBad(t *testing.T, cache string) {
	t.Helper()
	dir := filepath.Join(cache, "wpvulnerability", "plugin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for slug, body := range badEntries {
		if err := os.WriteFile(filepath.Join(dir, strings.TrimSuffix(slug, "!")+".json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCorruptCacheEntries(t *testing.T) {
	routes := map[string]string{}
	fp := fingerprint.Result{Tech: []string{"wordpress"}, Components: []fingerprint.Component{{Type: "plugin", Slug: "contact-form-7", Version: "5.3.1"}}}
	for slug := range badEntries {
		slug = strings.TrimSuffix(slug, "!")
		routes["/plugin/"+slug+"/"] = `{"error":0,"data":{"name":"P","vulnerability":[{"uuid":"` + slug + `","name":"P < 2.0 - Fresh Title","operator":{"max_version":"2.0","max_operator":"lt","unfixed":"0"},"source":[],"impact":{}}]}}`
		fp.Components = append(fp.Components, fingerprint.Component{Type: "plugin", Slug: slug, Version: "1.0"})
	}
	f := newFakeAPI(t, routes)
	cache := t.TempDir()
	ctx := context.Background()

	// Cache contact-form-7 properly, then plant the bad entries.
	newAdvisor(f, cache).Advise(ctx, base, fingerprint.Result{Tech: fp.Tech, Components: fp.Components[:1]})
	seedBad(t, cache)

	// Offline: no panic; the bad entries count as missing, with a warning.
	a := newAdvisor(f, cache)
	a.Client.Offline = true
	hits := f.hits.Load()
	fs, warnings := a.Advise(ctx, base, fp)
	if f.hits.Load() != hits {
		t.Error("offline made requests")
	}
	if _, ok := byID(fs)["vuln-plugin-contact-form-7"]; !ok {
		t.Errorf("good cache entry not used offline: %v", keys(byID(fs)))
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "not cached for 7 components (1 cached by an older Tuner)") {
		t.Errorf("offline warnings = %v", warnings)
	}

	// Online: every bad entry is fetched again and rewritten.
	fs, warnings = newAdvisor(f, cache).Advise(ctx, base, fp)
	if len(warnings) != 0 {
		t.Errorf("online warnings = %v", warnings)
	}
	got := byID(fs)
	for slug := range badEntries {
		slug = strings.TrimSuffix(slug, "!")
		if !f.requested("/plugin/" + slug + "/") {
			t.Errorf("%s: bad cache entry was not refetched", slug)
		}
		v, ok := got["vuln-plugin-"+slug]
		if !ok || v.Advisories[0].Title != "P < 2.0 - Fresh Title" {
			t.Errorf("%s: finding %+v", slug, v)
		}
	}

	// And the rewritten entries now serve offline.
	a = newAdvisor(f, cache)
	a.Client.Offline = true
	if _, warnings = a.Advise(ctx, base, fp); len(warnings) != 0 {
		t.Errorf("offline after refetch: %v", warnings)
	}
}

func TestVulnFindingNilRecord(t *testing.T) {
	a := &Advisor{Client: &Client{}}
	if _, ok := a.vulnFinding(base, &lookup{component: component{kind: "plugin", slug: "x", version: "1.0"}}); ok {
		t.Error("a nil record produced a finding")
	}
}
