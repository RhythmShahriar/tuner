// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSafeName(t *testing.T) {
	for key, want := range map[string]string{
		"contact-form-7": "contact-form-7",
		"6.4.1":          "6.4.1",
		"con":            "con_",
		"CON":            "CON_",
		"Aux":            "Aux_",
		"nul.x":          "nul_.x",
		"com1":           "com1_",
		"lpt9":           "lpt9_",
		"console":        "console",
		"com10":          "com10",
		"a/b@1.0":        "a~b@1.0",
		"a_b/c@1.0":      "a_b~c@1.0",
		"a b:c":          "a_b_c",
		"../etc":         "..~etc",
		"":               "",
		"..":             "",
	} {
		if got := SafeName(key); got != want {
			t.Errorf("SafeName(%q) = %q, want %q", key, got, want)
		}
	}
	s := &Store{Dir: "/c"}
	if got := s.Path("wpvulnerability/plugin", "con"); got != filepath.Join("/c", "wpvulnerability", "plugin", "con_.json") {
		t.Errorf("Path = %q", got)
	}
}

type rec struct{ Vulns []string }

func (r *rec) Valid() bool { return r != nil && r.Vulns != nil }

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	var calls atomic.Int32
	fetch := func(context.Context) (*rec, error) { calls.Add(1); return &rec{Vulns: []string{"a"}}, nil }

	s := &Store{Dir: dir, TTL: time.Hour, Format: 2}
	if v, info, err := Load(s, ctx, "k", "x", fetch); err != nil || info.Stale || len(v.Vulns) != 1 {
		t.Fatalf("first load: %v %+v %v", v, info, err)
	}
	// Shared in memory, then served from disk by a new store.
	Load(s, ctx, "k", "x", fetch)
	Load(&Store{Dir: dir, TTL: time.Hour, Format: 2}, ctx, "k", "x", fetch)
	if calls.Load() != 1 {
		t.Errorf("%d fetches, want 1", calls.Load())
	}
	e, ok, _ := Read[*rec](s, "k", "x")
	if !ok || e.Key != "x" || e.Format != 2 {
		t.Errorf("entry %+v", e)
	}

	// Another format: refetched online, an error offline.
	if _, _, err := Load(&Store{Dir: dir, TTL: time.Hour, Format: 3, Offline: true}, ctx, "k", "x", fetch); !errors.Is(err, ErrOldFormat) {
		t.Errorf("old format offline: %v", err)
	}
	Load(&Store{Dir: dir, TTL: time.Hour, Format: 3}, ctx, "k", "x", fetch)
	if calls.Load() != 2 {
		t.Errorf("old format not refetched: %d fetches", calls.Load())
	}

	// Stale and the fetch fails: the old copy, marked stale.
	e3, _, _ := Read[*rec](&Store{Dir: dir, Format: 3}, "k", "x")
	e3.Fetched = e3.Fetched.Add(-2 * time.Hour)
	if err := WriteJSON(filepath.Join(dir, "k", "x.json"), e3); err != nil {
		t.Fatal(err)
	}
	failing := func(context.Context) (*rec, error) { return nil, errors.New("down") }
	if v, info, err := Load(&Store{Dir: dir, TTL: time.Hour, Format: 3}, ctx, "k", "x", failing); err != nil || !info.Stale ||
		v == nil || time.Since(info.Fetched) < 2*time.Hour {
		t.Errorf("stale fallback: %v %+v %v", v, info, err)
	}
	if _, _, err := Load(&Store{Dir: dir, TTL: time.Hour, Format: 3, Force: true}, ctx, "k", "x", failing); err == nil {
		t.Error("a forced refresh hid the failure")
	}

	// Unusable files count as missing.
	for name, body := range map[string]string{"null": "null", "empty": "{}", "bare": `{"vulns":[]}`, "nodata": `{"format":3,"fetched":"2026-01-01T00:00:00Z"}`} {
		if err := os.WriteFile(filepath.Join(dir, "k", name+".json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := Read[*rec](&Store{Dir: dir, Format: 3}, "k", name); ok {
			t.Errorf("%s: unusable entry served", name)
		}
	}

	var keys []string
	if err := s.Entries(func(kind, key string) error { keys = append(keys, kind+"/"+key); return nil }); err != nil || len(keys) != 5 {
		t.Errorf("Entries: %v %v", keys, err)
	}
	if err := (&Store{Dir: filepath.Join(dir, "missing")}).Entries(func(string, string) error { return nil }); err != nil {
		t.Errorf("Entries on a missing dir: %v", err)
	}
}

func TestMemoBounded(t *testing.T) {
	s := &Store{TTL: time.Hour, MaxMemo: 3}
	ctx := context.Background()
	var calls atomic.Int32
	fetch := func(context.Context) (int, error) { return int(calls.Add(1)), nil }
	for i := range 5 {
		Load(s, ctx, "k", fmt.Sprint(i), fetch)
	}
	if n := s.memo.len(); n != 3 {
		t.Errorf("memo holds %d lookups, want 3", n)
	}
	// 4 is recent, so remembered; 0 was evicted, so fetched again.
	Load(s, ctx, "k", "4", fetch)
	if calls.Load() != 5 {
		t.Errorf("recent lookup refetched: %d calls", calls.Load())
	}
	Load(s, ctx, "k", "0", fetch)
	if calls.Load() != 6 {
		t.Errorf("evicted lookup not refetched: %d calls", calls.Load())
	}
	if l := newLRU(0); l.max != DefaultMaxMemo || DefaultMaxMemo != 2000 {
		t.Errorf("default memo size %d", l.max)
	}
}

func TestMemoExpires(t *testing.T) {
	s := &Store{TTL: time.Hour}
	ctx := context.Background()
	var calls atomic.Int32
	fail := func(context.Context) (int, error) { calls.Add(1); return 0, errors.New("down") }
	Load(s, ctx, "k", "x", fail)
	Load(s, ctx, "k", "x", fail)
	if calls.Load() != 1 {
		t.Fatalf("failure not shared: %d calls", calls.Load())
	}
	// A failure is retried after a minute, so a long-running process recovers.
	s.mu.Lock()
	s.memo.get("k/x").at = time.Now().Add(-2 * errorMemo)
	s.mu.Unlock()
	Load(s, ctx, "k", "x", fail)
	if calls.Load() != 2 {
		t.Errorf("old failure not retried: %d calls", calls.Load())
	}
}

// TestKeyCollision checks that two keys sharing a file name never get
// each other's data: "/" has its own escape and Read checks the stored
// key for the characters that still collide.
func TestKeyCollision(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir, TTL: time.Hour, Format: 1}
	if a, b := s.Path("packagist", "foo_bar/baz@1.0"), s.Path("packagist", "foo/bar_baz@1.0"); a == b {
		t.Errorf("foo_bar/baz and foo/bar_baz share %s", a)
	}
	// "a:b" and "a b" both clean up to a_b.
	if err := Write(s, "k", "a:b", &rec{Vulns: []string{"GHSA-1"}}); err != nil {
		t.Fatal(err)
	}
	if e, ok, old := Read[*rec](s, "k", "a b"); ok || old || e.Data != nil {
		t.Errorf("a b served a:b's entry: %+v ok %v old %v", e, ok, old)
	}
	if e, ok, _ := Read[*rec](s, "k", "a:b"); !ok || e.Data.Vulns[0] != "GHSA-1" {
		t.Errorf("a:b: %+v ok %v", e, ok)
	}
	// The other key loads its own data, which then replaces the file.
	v, _, err := Load(s, context.Background(), "k", "a b", func(context.Context) (*rec, error) { return &rec{Vulns: []string{}}, nil })
	if err != nil || len(v.Vulns) != 0 {
		t.Errorf("a b: %v %v", v, err)
	}
	// An entry written before keys were stored can't be checked; it is
	// served as before.
	if err := os.WriteFile(filepath.Join(dir, "k", "legacy.json"), []byte(`{"format":1,"fetched":"2026-10-01T00:00:00Z","data":{"Vulns":["x"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := Read[*rec](s, "k", "legacy"); !ok {
		t.Error("keyless entry refused")
	}
}
