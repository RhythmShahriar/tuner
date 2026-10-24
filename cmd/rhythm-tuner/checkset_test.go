// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
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

// packRelease serves a signed check pack holding check, and points Tuner
// at it with an empty cache. The pack retires every built-in check, so
// its one check may stand in for them.
func packRelease(t *testing.T, check, minTuner string) {
	t.Helper()
	retired, _ := json.Marshal(builtInIDs())
	servePack(t, `{"min_tuner": "`+minTuner+`", "retired": `+string(retired)+`}`, check, testPackKey)
}

// servePack serves a pack built from config (pack.json) and check, signed
// with key unless key is nil, and trusts testPackKey.
func servePack(t *testing.T, config, check string, key ed25519.PrivateKey) {
	t.Helper()
	src := fstest.MapFS{
		checkpack.ConfigName: {Data: []byte(config)},
		"leaks/pack.yaml":    {Data: []byte(check)},
	}
	b, err := checkpack.Build(src, "feedfacecafe", time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
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
// checks are refused with a warning, and the built-in checks run.
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
