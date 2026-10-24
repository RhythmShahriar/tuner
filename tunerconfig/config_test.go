// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package tunerconfig

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func env(vars map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := vars[k]; return v, ok }
}

func TestParse(t *testing.T) {
	data := `
targets: [https://staging.example.com, ./site]
profile: Quick
rate: 0
concurrency: 4
fail_on: HIGH
min_confidence: confirmed
baseline: base.json
headers:
  X-Team: web
  Authorization: Bearer ${TUNER_TOKEN}
tags: [leak]
exclude_tags: [headers]
ids: [leak-*]
exclude_ids: [leak-git]
ignore:
  - id: leak-dotenv
    reason: demo keys
    until: 2026-12-31
  - path: /backup/*.zip
    reason: an empty archive
`
	c, err := Parse([]byte(data), "ci/.tuner.yml", env(map[string]string{"TUNER_TOKEN": "s3cret"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Path != "ci/.tuner.yml" || c.Profile != "quick" || c.FailOn != "high" || c.MinConfidence != "confirmed" ||
		c.Rate == nil || *c.Rate != 0 || c.Concurrency == nil || *c.Concurrency != 4 ||
		c.Baseline != filepath.Join("ci", "base.json") || !slices.Equal(c.Targets, []string{"https://staging.example.com", "./site"}) ||
		!slices.Equal(c.Tags, []string{"leak"}) || !slices.Equal(c.ExcludeTags, []string{"headers"}) ||
		!slices.Equal(c.IDs, []string{"leak-*"}) || !slices.Equal(c.ExcludeIDs, []string{"leak-git"}) || len(c.Ignore) != 2 {
		t.Errorf("config: %+v", c)
	}
	if !slices.Equal(c.Headers, []string{"Authorization: Bearer s3cret", "X-Team: web"}) {
		t.Errorf("headers: %q", c.Headers)
	}

	empty, err := Parse(nil, ".tuner.yml", env(nil))
	if err != nil || empty.Rate != nil || empty.Profile != "" {
		t.Errorf("empty file: %+v, %v", empty, err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, c := range []struct{ data, want string }{
		{"fail_on: high\nfial_on: low\n", `.tuner.yml line 2: unknown key "fial_on"`},
		{"ignore:\n  - id: x\n    reson: typo\n", `.tuner.yml line 3: unknown key "reson"`},
		{"profile: turbo", `.tuner.yml: profile: "turbo": want quick or default`},
		{"fail_on: urgent", `fail_on: "urgent": want critical, high, medium, low or info`},
		{"min_confidence: sure", `min_confidence: "sure": want confirmed or likely`},
		{"rate: -1", "rate: want 0 or more"},
		{"concurrency: 0", "concurrency: want 1 or more"},
		{"rate: fast", ".tuner.yml line 1: cannot unmarshal"},
		{"targets: ['']", "targets: a target is empty"},
		{"ids: ['[']", `ids: bad pattern "["`},
		{"headers:\n  Bad Name: x", `headers: "Bad Name" is not a valid header name`},
		{"ignore:\n  - id: leak-dotenv\n", "ignore 1 (leak-dotenv): needs a reason"},
		{"ignore:\n  - reason: why\n", "ignore 1: needs an id or a path"},
		{"ignore:\n  - id: x\n    reason: y\n    until: 31/12/2026\n", `ignore 1 (x): until "31/12/2026": want a date such as 2026-12-31`},
		{"profile: [", ".tuner.yml: yaml:"},
		{"fail_on: high\n---\nrate: -5\nbogus: 1\n", ".tuner.yml: holds more than one YAML document"},
		{"fail_on: high\n---\nprofile: [\n", ".tuner.yml: yaml:"},
	} {
		_, err := Parse([]byte(c.data), ".tuner.yml", env(nil))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: got %v, want %q", c.data, err, c.want)
		}
	}
}

// A trailing "---" is an empty document, not a second one.
func TestParseTrailingSeparator(t *testing.T) {
	if _, err := Parse([]byte("fail_on: high\n---\n"), ".tuner.yml", env(nil)); err != nil {
		t.Error(err)
	}
}

// A type error never shows any of the value, which may be a token.
func TestTypeErrorHidesValue(t *testing.T) {
	_, err := Parse([]byte(`headers: "Bearer abcdefghijkl"`), ".tuner.yml", env(nil))
	if err == nil || strings.Contains(err.Error(), "Bearer") || strings.Contains(err.Error(), "abc") ||
		!strings.Contains(err.Error(), ".tuner.yml line 1: cannot unmarshal !!str into map[string]string") {
		t.Errorf("got %v", err)
	}
}

func TestHeaderEnv(t *testing.T) {
	for _, c := range []struct {
		value string
		vars  map[string]string
		want  string // the header, or the error
	}{
		{"Bearer ${TUNER_TOKEN}", map[string]string{"TUNER_TOKEN": "abc"}, "Authorization: Bearer abc"},
		{"${TUNER_A}:${TUNER_B}", map[string]string{"TUNER_A": "u", "TUNER_B": "p"}, "Authorization: u:p"},
		{"$TOKEN stays", nil, "Authorization: $TOKEN stays"},
		{"Bearer ${TUNER_TOKEN}", nil, "headers: Authorization uses ${TUNER_TOKEN}, which is not set"},
		{"Bearer ${TUNER_TOKEN}", map[string]string{"TUNER_TOKEN": ""}, "headers: Authorization uses ${TUNER_TOKEN}, which is not set"},
		{"Bearer ${1X}", nil, "uses ${1X}, which is not a variable name"},
		{"a${TUNER_NL}b", map[string]string{"TUNER_NL": "line\nbreak-secret"}, "headers: the value of Authorization has a line break or control character"},
		// An untrusted .tuner.yml can't reach a variable set for something else.
		{"Bearer ${GITHUB_TOKEN}", map[string]string{"GITHUB_TOKEN": "ghs_secret"}, "headers: Authorization uses ${GITHUB_TOKEN}; only variables that start with TUNER_ can be used, so set TUNER_GITHUB_TOKEN and name that"},
		{"${tuner_x}", map[string]string{"tuner_x": "low"}, "only variables that start with TUNER_"},
	} {
		cfg, err := Parse([]byte("headers:\n  Authorization: "+c.value+"\n"), ".tuner.yml", env(c.vars))
		got := ""
		if err != nil {
			got = err.Error()
		} else {
			got = strings.Join(cfg.Headers, "|")
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%q: got %q, want %q", c.value, got, c.want)
		}
		for _, v := range c.vars {
			if err != nil && v != "" && strings.Contains(got, v) && !strings.Contains(c.want, v) {
				t.Errorf("%q: the error shows the value: %s", c.value, got)
			}
		}
	}
}

func TestIgnores(t *testing.T) {
	c, err := Parse([]byte(`
ignore:
  - id: leak-dotenv
    reason: demo keys
    until: 2026-09-30
  - id: leak-*
    path: /backup/*.zip
    reason: an empty archive
    until: 2026-10-24
  - path: old/*
    reason: no expiry
`), ".tuner.yml", env(nil))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 24, 23, 0, 0, 0, time.UTC)
	active, expired := c.Ignores(now)
	if len(active) != 2 || len(expired) != 1 || expired[0].ID != "leak-dotenv" {
		t.Fatalf("active %v, expired %v", active, expired)
	}
	if got := expired[0].Note(); got != "ignore for leak-dotenv expired 2026-09-30: demo keys" {
		t.Errorf("note %q", got)
	}
	if _, expired := c.Ignores(now.AddDate(0, 0, 1)); len(expired) != 2 {
		t.Errorf("the next day the second entry expires too: %v", expired)
	}
	if _, expired := c.Ignores(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)); len(expired) != 0 {
		t.Errorf("an entry applies through its until day: %v", expired)
	}

	for _, m := range []struct {
		ig       Ignore
		id, path string
		want     bool
	}{
		{c.Ignore[0], "leak-dotenv", "/.env", true},
		{c.Ignore[0], "leak-git", "/.env", false},
		{c.Ignore[1], "leak-backup", "/backup/site.zip", true},
		{c.Ignore[1], "leak-backup", "/backup/deep/site.zip", false},
		{c.Ignore[1], "hdr-csp", "/backup/site.zip", false},
		{c.Ignore[2], "anything", "/old/x.php", true},
	} {
		if got := m.ig.Matches(m.id, m.path); got != m.want {
			t.Errorf("%+v on %s %s: %v", m.ig, m.id, m.path, got)
		}
	}
	if got := c.Ignore[1].Note(); !strings.HasPrefix(got, "ignore for leak-* /backup/*.zip expired") {
		t.Errorf("note %q", got)
	}
}

func TestFindAndLoad(t *testing.T) {
	dir := t.TempDir()
	if p, err := Find(dir); p != "" || err != nil {
		t.Errorf("no file: %q, %v", p, err)
	}
	os.WriteFile(filepath.Join(dir, DefaultName), []byte("headers:\n  X-Key: ${TUNER_CONFIG_TEST_KEY}\n"), 0o600)
	p, err := Find(dir)
	if err != nil || p != filepath.Join(dir, DefaultName) {
		t.Fatalf("%q, %v", p, err)
	}
	t.Setenv("TUNER_CONFIG_TEST_KEY", "k")
	c, err := Load(p)
	if err != nil || !slices.Equal(c.Headers, []string{"X-Key: k"}) {
		t.Errorf("%+v, %v", c, err)
	}
	if _, err := Load(filepath.Join(dir, "missing.yml")); err == nil {
		t.Error("a missing file loads")
	}
	sub := filepath.Join(t.TempDir(), DefaultName)
	os.Mkdir(sub, 0o755)
	if _, err := Find(filepath.Dir(sub)); err == nil {
		t.Error("a folder named .tuner.yml is a config")
	}
}

// deep is still accepted although the message leaves it out.
func TestProfileDeepAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".tuner.yml")
	if err := os.WriteFile(path, []byte("profile: Deep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil || c.Profile != "deep" {
		t.Errorf("profile deep: %+v, %v", c, err)
	}
}
