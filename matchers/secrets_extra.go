// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package matchers

import (
	"regexp"
	"sort"
	"strings"
)

// The Tuner supplement covers the few credentials that kit/secrets v0.6.0
// still prints in clear: env names run together with PW or KEYS (dbpw,
// LICENSEKEYS) and the token maps in composer auth.json. It runs on text
// the kit has already redacted, so it only adds to the kit rules and never
// overrides them. Drop each rule once the kit ships it.

var (
	// Any NAME=value line; extraEnvName decides whether NAME is a secret.
	extraEnvRe = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z][A-Za-z0-9_.\-]*)[ \t]*=[ \t]*["']?([^\s"'#]+)`)
	// Composer auth.json token maps: {"github-oauth": {"github.com": "token"}}.
	// http-basic passwords and the bitbucket-oauth consumer key and secret
	// are JSON fields with secret names, which the kit already masks.
	composerRe = regexp.MustCompile(`"(github-oauth|gitlab-oauth|gitlab-token|bearer)"\s*:\s*\{([^{}]*)\}`)
	// composerPairRe reads one "host": "token" pair inside such a map.
	composerPairRe = regexp.MustCompile(`"[^"]+"\s*:\s*"([^"]+)"`)
)

// Words that end in KEYS but name nothing secret.
var notKeyWords = map[string]bool{"HOTKEYS": true, "MONKEYS": true, "TURKEYS": true, "DONKEYS": true, "WHISKEYS": true, "JOCKEYS": true, "HOCKEYS": true}

// extraEnvName reports whether an env name the kit misses still names a
// credential. Names are split into words at _ . and -, compared in upper
// case: a word longer than PW that ends in PW (DBPW) or a word longer than
// KEYS that ends in KEYS (LICENSEKEYS). The kit already covers PW and KEY
// as whole words, PWD, DSN and CREDENTIAL anywhere.
func extraEnvName(name string) bool {
	for _, w := range strings.FieldsFunc(strings.ToUpper(name), func(r rune) bool { return r == '_' || r == '.' || r == '-' }) {
		switch {
		case strings.HasSuffix(w, "PW") && len(w) > 2:
			return true
		case strings.HasSuffix(w, "KEYS") && len(w) > 4 && !notKeyWords[w]:
			return true
		}
	}
	return false
}

// skipValue mirrors the kit's placeholder rules and skips values the kit
// has already masked.
func skipValue(v string) bool {
	return len(v) < 3 || placeholders[strings.ToLower(v)] || strings.HasPrefix(v, "${") || strings.Contains(v, "•")
}

// Values that look like secrets but are only placeholders.
var placeholders = map[string]bool{"null": true, "true": true, "false": true, "none": true, "empty": true}

// span is a secret found in the redacted text: its place and what it is.
type span struct {
	start, end int
	secret     Secret
}

// extraSpans finds supplement secrets in s, sorted and without overlaps.
func extraSpans(s string) []span {
	var spans []span
	add := func(kind, name string, vs, ve, keep int) {
		v := s[vs:ve]
		if skipValue(v) {
			return
		}
		spans = append(spans, span{vs, ve, Secret{Kind: kind, Name: name, Masked: Mask(v, keep)}})
	}
	for _, m := range composerRe.FindAllStringSubmatchIndex(s, -1) {
		section := s[m[2]:m[3]]
		body := s[m[4]:m[5]]
		for _, p := range composerPairRe.FindAllStringSubmatchIndex(body, -1) {
			add("composer-auth", section, m[4]+p[2], m[4]+p[3], 2)
		}
	}
	for _, m := range extraEnvRe.FindAllStringSubmatchIndex(s, -1) {
		if extraEnvName(s[m[2]:m[3]]) {
			add("env", s[m[2]:m[3]], m[4], m[5], 2)
		}
	}
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	out := spans[:0]
	end := -1
	for _, sp := range spans {
		if sp.start >= end {
			out = append(out, sp)
			end = sp.end
		}
	}
	return out
}

// redactExtra replaces every supplement secret in s with its masked form.
func redactExtra(s string) string {
	spans := extraSpans(s)
	if len(spans) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, sp := range spans {
		b.WriteString(s[last:sp.start])
		b.WriteString(sp.secret.Masked)
		last = sp.end
	}
	b.WriteString(s[last:])
	return b.String()
}
