// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package matchers

import (
	"regexp"
	"sort"
	"strings"
)

// The Tuner supplement covers credentials that kit/secrets v0.5.0 still
// prints in clear. It runs on text the kit has already redacted, so it only
// adds to the kit rules and never overrides them. Drop each rule once the
// kit ships it (planned for kit v0.6).

var (
	// Any NAME=value line; extraEnvName decides whether NAME is a secret.
	extraEnvRe = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z][A-Za-z0-9_.\-]*)[ \t]*=[ \t]*["']?([^\s"'#]+)`)
	// redis://:pass@host. The kit rule needs a user before the colon.
	extraURLRe = regexp.MustCompile(`\b[a-z][a-z0-9+]*://:([^@\s/"']+)@`)
	// Composer auth.json token maps: {"github-oauth": {"github.com": "token"}}.
	// http-basic passwords are "password" fields, which the kit already masks.
	composerRe     = regexp.MustCompile(`"(github-oauth|gitlab-oauth|gitlab-token|bearer|bitbucket-oauth)"\s*:\s*\{([^{}]*)\}`)
	composerPairRe = regexp.MustCompile(`"[^"]+"\s*:\s*"([^"]+)"`)
	// bitbucket-oauth nests {"consumer-key": ..., "consumer-secret": ...};
	// the kit masks the secret but not the key.
	consumerKeyRe = regexp.MustCompile(`"(consumer-key)"\s*:\s*"([^"]+)"`)
)

// Words that end in KEY but name nothing secret.
var notKeyWords = map[string]bool{"HOTKEY": true, "MONKEY": true, "TURKEY": true, "DONKEY": true, "WHISKEY": true, "JOCKEY": true, "HOCKEY": true}

// extraEnvName reports whether an env name the kit rule misses still names
// a credential. Names are split into words at _ . and -, compared in upper
// case: a word ending in PW or PWD (MYSQL_PWD, DBPW), a word ending in KEY
// or KEYS that is not KEY alone (APIKEY; the kit already covers _KEY), a
// word containing DSN (SENTRY_DSN) or a word starting with CREDENTIAL.
// KEYBOARD_LAYOUT is not a secret: no word ends in KEY.
func extraEnvName(name string) bool {
	for _, w := range strings.FieldsFunc(strings.ToUpper(name), func(r rune) bool { return r == '_' || r == '.' || r == '-' }) {
		switch {
		case strings.HasSuffix(w, "PW"), strings.HasSuffix(w, "PWD"):
			return true
		case (strings.HasSuffix(w, "KEY") && len(w) > 3 || strings.HasSuffix(w, "KEYS") && len(w) > 4) && !notKeyWords[strings.TrimSuffix(w, "S")]:
			return true
		case strings.Contains(w, "DSN"), strings.HasPrefix(w, "CREDENTIAL"):
			return true
		}
	}
	return false
}

// pathLike reports whether v looks like a file path rather than a secret,
// as in GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp.json.
func pathLike(v string) bool {
	return strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") ||
		strings.HasPrefix(v, "~/") || strings.HasSuffix(strings.ToLower(v), ".json")
}

// skipValue mirrors the kit's placeholder rules and skips values the kit
// has already masked.
func skipValue(v string) bool {
	return len(v) < 3 || placeholders[strings.ToLower(v)] || strings.HasPrefix(v, "${") || strings.Contains(v, "•")
}

// Values that look like secrets but are only placeholders.
var placeholders = map[string]bool{"null": true, "true": true, "false": true, "none": true, "empty": true}

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
	for _, m := range extraURLRe.FindAllStringSubmatchIndex(s, -1) {
		add("url-credentials", "", m[2], m[3], 2)
	}
	for _, m := range composerRe.FindAllStringSubmatchIndex(s, -1) {
		section := s[m[2]:m[3]]
		body := s[m[4]:m[5]]
		for _, p := range composerPairRe.FindAllStringSubmatchIndex(body, -1) {
			add("composer-auth", section, m[4]+p[2], m[4]+p[3], 2)
		}
	}
	for _, m := range consumerKeyRe.FindAllStringSubmatchIndex(s, -1) {
		add("composer-auth", s[m[2]:m[3]], m[4], m[5], 2)
	}
	for _, m := range extraEnvRe.FindAllStringSubmatchIndex(s, -1) {
		name, v := s[m[2]:m[3]], s[m[4]:m[5]]
		if !extraEnvName(name) || strings.Contains(strings.ToUpper(name), "CREDENTIAL") && pathLike(v) {
			continue
		}
		add("env", name, m[4], m[5], 2)
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
