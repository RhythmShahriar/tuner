// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
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

// packRelease serves a signed check pack holding check and points Tuner
// at it with an empty cache. The pack retires every built-in check, so
// its one check may stand in for them.
func packRelease(t *testing.T, check, minTuner string) {
	t.Helper()
	retired, _ := json.Marshal(builtInIDs())
	servePack(t, `{"min_tuner": "`+minTuner+`", "retired": `+string(retired)+`}`, check, testPackKey)
}

// servePack serves a pack built from config (pack.json) and check, signed
// with key unless key is nil and trusts testPackKey.
func servePack(t *testing.T, config, check string, key ed25519.PrivateKey) {
	t.Helper()
	servePackWith(t, config, check, checkpack.Extras{}, key)
}

// servePackWith is servePack with fingerprint data and local rules.
func servePackWith(t *testing.T, config, check string, x checkpack.Extras, key ed25519.PrivateKey) {
	t.Helper()
	src := fstest.MapFS{
		checkpack.ConfigName: {Data: []byte(config)},
		"leaks/pack.yaml":    {Data: []byte(check)},
	}
	b, err := checkpack.BuildWith(src, x, "feedfacecafe", time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if key != nil {
		b.Sign(key)
	}
	trustTestKey(t)
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

// testPackKey signs the test packs in place of the release key.
var testPackKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))

func trustTestKey(t *testing.T) {
	t.Helper()
	old := packKeys
	packKeys = []ed25519.PublicKey{testPackKey.Public().(ed25519.PublicKey)}
	t.Cleanup(func() { packKeys = old })
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

// Packs that are unsigned, signed by an unknown key or short of built-in
// checks are refused with a warning and the built-in checks run.
func TestScanRefusesUntrustedPack(t *testing.T) {
	retired, _ := json.Marshal(builtInIDs())
	full := `{"min_tuner": "0.2.0", "retired": ` + string(retired) + `}`
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	for name, tc := range map[string]struct {
		config string
		key    ed25519.PrivateKey
		want   string
	}{
		"unsigned":    {full, nil, "checks-sha256.txt.sig: HTTP 404"},
		"unknown key": {full, other, "checks-sha256.txt is not signed by a trusted key"},
		"short":       {`{"min_tuner": "0.2.0"}`, testPackKey, "lacks built-in checks hdr-content-type-options-missing, "},
	} {
		t.Run(name, func(t *testing.T) {
			servePack(t, tc.config, packCheck, tc.key)
			rep, errs := scanReport(t, leakySite(t).URL)
			if rep.CheckSet != "built-in" || !rep.has("leak-dotenv") {
				t.Errorf("untrusted pack used: %+v", rep)
			}
			if !strings.Contains(errs, tc.want) || !strings.Contains(errs, "using built-in checks") {
				t.Errorf("stderr lacks %q:\n%s", tc.want, errs)
			}
		})
	}
}

// TUNER_CHECKS_INSECURE=1 lets a private fork use its own unsigned pack,
// and says so on every run.
func TestScanInsecurePack(t *testing.T) {
	retired, _ := json.Marshal(builtInIDs())
	servePack(t, `{"min_tuner": "0.2.0", "retired": `+string(retired)+`}`, packCheck, nil)
	t.Setenv("TUNER_CHECKS_INSECURE", "1")
	site := leakySite(t).URL
	for range 2 {
		rep, errs := scanReport(t, site)
		if rep.CheckSet != "pack" || !strings.Contains(errs, insecureWarning) {
			t.Errorf("insecure: %+v\n%s", rep, errs)
		}
	}
}

// hangingHost points Tuner at a pack host that accepts requests and never
// answers and counts them.
func hangingHost(t *testing.T) *atomic.Int32 {
	t.Helper()
	var hits atomic.Int32
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case <-r.Context().Done():
		case <-done:
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(done) }) // runs first, so Close doesn't wait
	t.Setenv("TUNER_CHECKS_URL", srv.URL)
	return &hits
}

// expirePack makes the cached pack older than the TTL.
func expirePack(t *testing.T) {
	t.Helper()
	path := filepath.Join(checkpack.DefaultCacheDir(), "pack.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	st["checked"] = time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	data, _ = json.Marshal(st)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestHangingPackHostBacksOff(t *testing.T) {
	packRelease(t, packCheck, "0.2.0")
	if set, err := loadCheckSet("", true, false, "test", nil); err != nil || set.source != setPack {
		t.Fatalf("set=%+v err=%v", set, err)
	}
	expirePack(t)
	hits := hangingHost(t)

	start := time.Now()
	set, err := loadCheckSet("", true, false, "test", nil)
	if took := time.Since(start); took > 3500*time.Millisecond {
		t.Errorf("first run waited %v", took)
	}
	want := "check pack host unreachable, using pack from 2026-10-01"
	if err != nil || set.source != setPack || !slices.Contains(set.alerts, want) || !slices.Contains(set.warnings, want) {
		t.Fatalf("first run: set=%+v err=%v", set, err)
	}

	// Within the back-off: no request, no repeat of the warning.
	n := hits.Load()
	set, err = loadCheckSet("", true, false, "test", nil)
	if err != nil || set.source != setPack || len(set.warnings) != 0 || hits.Load() != n {
		t.Errorf("second run: set=%+v err=%v, %d requests", set, err, hits.Load()-n)
	}
}

func TestUnreachablePackHostWithoutCache(t *testing.T) {
	trustTestKey(t)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}))
	t.Cleanup(srv.Close)
	t.Setenv("TUNER_CHECKS_URL", srv.URL)

	set, err := loadCheckSet("", true, false, "test", nil)
	want := []string{"check pack host unreachable, using built-in checks"}
	if err != nil || set.source != setBuiltIn || !slices.Equal(set.alerts, want) {
		t.Fatalf("set=%+v err=%v", set, err)
	}
	n := hits.Load()
	if set, _ := loadCheckSet("", true, false, "test", nil); len(set.warnings) != 0 || hits.Load() != n {
		t.Errorf("second run: %+v, %d requests", set.warnings, hits.Load()-n)
	}
}

// A pack's fingerprint data and local rules replace the built-in copies
// when the pack is in use and only then.
func TestPackDataAndLocalRules(t *testing.T) {
	retired, _ := json.Marshal(builtInIDs())
	servePackWith(t, `{"min_tuner": "0.2.0", "retired": `+string(retired)+`}`, packCheck, checkpack.Extras{
		Data:  fstest.MapFS{"rest-namespaces.json": {Data: []byte(`{"acme-forms/v1": "acme-forms"}`)}},
		Local: fstest.MapFS{"acme-backdoor.yaml": {Data: []byte("id: local-acme-backdoor\n")}},
	}, testPackKey)

	set, err := loadCheckSet("", true, false, "test", nil)
	if err != nil || set.source != setPack {
		t.Fatalf("source %v, err %v, warnings %v", set.source, err, set.warnings)
	}
	if data, ok := set.data("rest-namespaces.json"); !ok || !strings.Contains(string(data), "acme-forms") {
		t.Errorf("data = %q, %v", data, ok)
	}
	if _, ok := set.data("top-plugins.json"); ok {
		t.Error("a file the pack lacks should fall back to the built-in copy")
	}
	rules := set.localRules()
	if rules == nil {
		t.Fatal("no local rules from the pack")
	}
	if data, err := fs.ReadFile(rules, "acme-backdoor.yaml"); err != nil || !strings.Contains(string(data), "local-acme-backdoor") {
		t.Errorf("rule = %q, %v", data, err)
	}

	builtIn, err := loadCheckSet("", false, false, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := builtIn.data("rest-namespaces.json"); ok || builtIn.localRules() != nil {
		t.Error("built-in check set should use the binary's data and rules")
	}
}
