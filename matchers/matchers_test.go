// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package matchers

import (
	"net/http"
	"strings"
	"testing"
)

func TestCleanText(t *testing.T) {
	for in, want := range map[string]string{
		"plain text":                    "plain text",
		"tab\tkept":                     "tab\tkept",
		"osc\x1b]52;c;aGk=\x07end":      "osc�]52;c;aGk=�end",
		"del\x7f c1\u009b31m nel\u0085": "del� c1�31m nel�",
		"nl\ncr\r":                      "nl�cr�",
		"bad \xff utf8, ok ünïcode • …": "bad � utf8, ok ünïcode • …",
		"nul\x00":                       "nul�",
	} {
		if got := CleanText(in); got != want {
			t.Errorf("CleanText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSnippetStripsControlBytes(t *testing.T) {
	got := Snippet([]byte("APP_NAME=\x1b]52;c;ZWNobyBoaQ==\x07\nNEXT=1\tx \u009b2J"))
	if strings.ContainsAny(got, "\x1b\x07\u009b\n\t") {
		t.Errorf("Snippet kept control bytes: %q", got)
	}
	if want := "APP_NAME=�]52;c;ZWNobyBoaQ==� NEXT=1 x �2J"; got != want {
		t.Errorf("Snippet = %q, want %q", got, want)
	}
}

func compiled(t *testing.T, m Matcher) *Matcher {
	t.Helper()
	if err := m.Compile(); err != nil {
		t.Fatal(err)
	}
	return &m
}

func TestRegexEvidenceRedactedBeforeCut(t *testing.T) {
	// The token starts at rune 100, so the 120-rune snippet would cut it
	// to "sk_live_abcdefghijk", too short for the stripe rule to recognize.
	token := "sk_live_abcdefghijklmnopqrstuvwxyz123456"
	line := "STRIPE=" + strings.Repeat("x", 92) + " " + token + "\n"
	m := compiled(t, Matcher{Regex: `(?m)^[A-Z_]+=.+`})
	ok, ev := m.Match(&Response{Status: 200, Body: []byte(line)}, nil)
	if !ok {
		t.Fatal("no match")
	}
	if !strings.Contains(ev, "sk_live_•••••") {
		t.Errorf("masked form missing: %q", ev)
	}
	if strings.Contains(ev, "sk_live_a") || strings.Contains(ev, "abcdef") {
		t.Errorf("evidence leaks the token: %q", ev)
	}
}

func TestHeaderAndBlockEvidenceCleaned(t *testing.T) {
	h := http.Header{}
	h.Set("X-Debug", "on\x1b[2J")
	b := Block{All: []Matcher{{Header: map[string]string{"X-Debug": "on"}}}}
	if err := b.Compile(); err != nil {
		t.Fatal(err)
	}
	ok, ev := b.Match(&Response{Status: 200, Header: h}, nil)
	if !ok || len(ev) != 1 || ev[0] != "X-Debug: on�[2J" {
		t.Errorf("got %v %q", ok, ev)
	}
}

func TestMaskCleansKeptPrefix(t *testing.T) {
	if got := Mask("\x1b]52;c;secretvalue", 2); strings.ContainsRune(got, 0x1b) {
		t.Errorf("Mask kept ESC: %q", got)
	}
}
