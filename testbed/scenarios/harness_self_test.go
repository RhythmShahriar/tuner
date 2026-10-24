// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package scenarios

import (
	"encoding/json"
	"testing"
)

// Tests for the harness itself, so a broken assertion can't make every
// scenario pass.

func TestLookup(t *testing.T) {
	var doc any
	if err := json.Unmarshal([]byte(`{"target":"a","findings":[{"id":"x"},{"id":"y"}]}`), &doc); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]any{"target": "a", "findings.#": float64(2), "findings.1.id": "y"} {
		if got, ok := lookup(doc, path); !ok || got != want {
			t.Errorf("lookup(%s) = %v, %v; want %v", path, got, ok, want)
		}
	}
	for _, path := range []string{"nope", "findings.2.id", "target.x"} {
		if _, ok := lookup(doc, path); ok {
			t.Errorf("lookup(%s) found something", path)
		}
	}
	if ids := findingIDs(doc); len(ids) != 2 || ids[0] != "x" {
		t.Errorf("findingIDs = %v", ids)
	}
}

func TestExits(t *testing.T) {
	if got := exits(3); len(got) != 1 || got[0] != 3 {
		t.Errorf("exits(3) = %v", got)
	}
	if got := exits([]any{0, 1}); len(got) != 2 {
		t.Errorf("exits([0 1]) = %v", got)
	}
	if got := exits("three"); len(got) != 1 || got[0] != -999 {
		t.Errorf("a typo must never match, got %v", got)
	}
}

func TestTextCheck(t *testing.T) {
	id := func(s string) string { return s }
	c := textCheck{Contains: []string{"a"}, NotContains: []string{"b"}, Matches: []string{"^a"}, NotMatches: []string{`\x1b`}}
	if p := c.check("out", "abc", id); len(p) != 1 {
		t.Errorf("want only the not_contains problem, got %v", p)
	}
	if p := c.check("out", "a\x1b", id); len(p) != 1 {
		t.Errorf("want only the not_matches problem, got %v", p)
	}
	if p := c.check("out", "ac", id); len(p) != 0 {
		t.Errorf("want no problems, got %v", p)
	}
}

func TestMatchRoutes(t *testing.T) {
	routes := map[string]compiled{
		"/":       {body: []byte("home")},
		"/blog/*": {body: []byte("blog")},
		"/blog/x": {body: []byte("x")},
		"*":       {body: []byte("rest")},
	}
	for path, want := range map[string]string{"/": "home", "/blog/a": "blog", "/blog/x": "x", "/other": "rest"} {
		if r, ok := match(routes, path); !ok || string(r.body) != want {
			t.Errorf("match(%s) = %q, want %q", path, r.body, want)
		}
	}
	delete(routes, "*")
	if _, ok := match(routes, "/other"); ok {
		t.Error("without * an unknown path must not match")
	}
}

func TestPortPool(t *testing.T) {
	if _, err := newPortPool("9-1"); err == nil {
		t.Error("a reversed range must fail")
	}
	p, err := portsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.listen(make([]string, p.total+1)); err == nil {
		t.Error("asking for more ports than the range holds must fail")
	}
	lns, err := p.listen([]string{"127.0.0.1", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	a, b := portOf(lns[0]), portOf(lns[1])
	if a == b {
		t.Errorf("two listeners share port %d", a)
	}
	free := len(p.free)
	for _, l := range lns {
		_ = l.Close()
	}
	if len(p.free) != free+2 {
		t.Errorf("closing returned %d ports, want 2", len(p.free)-free)
	}
}
