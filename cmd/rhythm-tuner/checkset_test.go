package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/RhythmShahriar/tuner/checkpack"
)

// packCheck finds the same .env leak as the built-in leak-dotenv, under an
// ID that shows which check set ran.
const packCheck = `id: pack-dotenv
name: .env exposed (from the pack)
severity: critical
request:
  path: ["/.env"]
match:
  all:
    - status: 200
    - words: ["DB_PASSWORD"]
`

// packRelease serves a check pack holding check, and points Tuner at it
// with an empty cache.
func packRelease(t *testing.T, check, minTuner string) {
	t.Helper()
	src := fstest.MapFS{
		checkpack.ConfigName: {Data: []byte(`{"min_tuner": "` + minTuner + `"}`)},
		"leaks/pack.yaml":    {Data: []byte(check)},
	}
	b, err := checkpack.Build(src, "feedfacecafe", time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := b.Files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(data)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("TUNER_CHECKS_URL", srv.URL)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
}

type packReport struct {
	CheckSet  string `json:"check_set"`
	CheckPack string `json:"check_pack"`
	Findings  []struct{ ID string }
}

func scanReport(t *testing.T, args ...string) (packReport, string) {
	t.Helper()
	code, out, errs := tuner(t, append([]string{"scan", "--json", "--no-vulns"}, args...)...)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var rep packReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return rep, errs
}

func (r packReport) has(id string) bool {
	for _, f := range r.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestScanUsesCheckPack(t *testing.T) {
	packRelease(t, packCheck, "0.2.0")
	site := leakySite(t)

	rep, _ := scanReport(t, site.URL)
	if rep.CheckSet != "pack" || rep.CheckPack != "2026.10.01-120000" || !rep.has("pack-dotenv") || rep.has("leak-dotenv") {
		t.Errorf("with a pack: %+v", rep)
	}

	// Cached now: --offline still uses it.
	if rep, _ := scanReport(t, site.URL, "--offline"); rep.CheckSet != "pack" {
		t.Errorf("--offline ignored the cached pack: %+v", rep)
	}

	if rep, _ := scanReport(t, site.URL, "--no-check-updates"); rep.CheckSet != "built-in" || !rep.has("leak-dotenv") || rep.CheckPack != "" {
		t.Errorf("--no-check-updates: %+v", rep)
	}

	_, out, _ := tuner(t, "checks")
	if !strings.Contains(out, "pack-dotenv") || !strings.Contains(out, "Using check pack 2026.10.01-120000") {
		t.Errorf("checks listing:\n%s", out)
	}
	code, out, errs := tuner(t, "update")
	if !strings.Contains(out, "Checks: pack 2026.10.01-120000, 1 checks") {
		t.Errorf("update (exit %d):\n%s\n%s", code, out, errs)
	}
}

func TestScanFallsBackFromBadPack(t *testing.T) {
	// A pack for a newer Tuner. (Packs using unknown matchers are
	// rejected the same way; see the checkpack tests.)
	packRelease(t, packCheck, "99.0.0")
	old := version
	version = "0.3.0"
	defer func() { version = old }()
	rep, errs := scanReport(t, leakySite(t).URL)
	if rep.CheckSet != "built-in" || !rep.has("leak-dotenv") {
		t.Errorf("bad pack not replaced by built-in checks: %+v", rep)
	}
	if !strings.Contains(errs, "needs rhythm-tuner 99.0.0") || !strings.Contains(errs, "using built-in checks") {
		t.Errorf("no warning about the rejected pack:\n%s", errs)
	}
}

func TestScanOfflineWithoutPack(t *testing.T) {
	t.Setenv("TUNER_CHECKS_URL", "http://127.0.0.1:1")
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	rep, errs := scanReport(t, leakySite(t).URL, "--offline")
	if rep.CheckSet != "built-in" || strings.Contains(errs, "check pack") {
		t.Errorf("offline without a pack: %+v\n%s", rep, errs)
	}
}

func TestChecksDirOverridesPack(t *testing.T) {
	packRelease(t, packCheck, "0.2.0")
	rep, _ := scanReport(t, leakySite(t).URL, "--checks", "../../checks")
	if rep.CheckSet != "directory" || !rep.has("leak-dotenv") {
		t.Errorf("--checks: %+v", rep)
	}
}
