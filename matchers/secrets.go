// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package matchers

import (
	"cmp"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/secrets"
)

// Secret is a detected credential. The raw value never leaves this package.
// It is the kit type, so reports keep the same JSON shape across the
// rhythm tools.
type Secret = secrets.Secret

// FindSecrets returns every secret in b, masked and de-duplicated. The kit
// rules run first; the Tuner supplement then runs on the kit-redacted text,
// so a value both would catch is reported once, under the kit kind.
//
// Two secrets are the same when kind, name and raw value match. The masked
// form alone can't tell them apart: it keeps at most 4 characters, so two
// different OpenAI keys both read sk-p•••••. Only a SHA-256 of the raw
// value is kept, for no longer than FindSecrets runs.
func FindSecrets(b []byte) []Secret {
	s := string(b)
	red := secrets.Redact(s)
	var out []Secret
	seen := map[secretKey]bool{}
	add := func(sec Secret, raw string) {
		k := secretKey{sec, sha256.Sum256([]byte(raw))}
		if !seen[k] {
			seen[k] = true
			sec.Masked = CleanText(sec.Masked)
			out = append(out, sec)
		}
	}
	for _, ks := range kitSecrets(s, red) {
		add(ks.secret, ks.rest)
	}
	for _, sp := range extraSpans(red) {
		add(sp.secret, red[sp.start:sp.end])
	}
	return out
}

// secretKey identifies one credential: what the report shows plus a hash
// of the raw value, which is never stored or printed.
type secretKey struct {
	secret Secret
	sum    [sha256.Size]byte
}

// kitSecret is one kit match: the secret as the kit reports it and the
// part of the raw value its mask hides.
type kitSecret struct {
	secret Secret
	rest   string
}

// bullets ends every mask the kit writes.
const bullets = "•••••"

// kitSecrets lists every kit match in s, duplicates included, with the
// hidden part of each raw value. red is secrets.Redact(s).
//
// The kit reports secrets de-duplicated by their masked form, so the raw
// values come from lining s up with red: red is s with each value
// replaced by its first few characters and the bullets. Two values with
// the same kind, name and mask share those first characters, so the
// hidden rest tells them apart. When the texts don't line up (s already
// holds bullets or invalid UTF-8, or two values touch), each kit secret
// is listed once with no rest, as the kit reports them.
func kitSecrets(s, red string) []kitSecret {
	found := secrets.FindSecrets([]byte(s))
	fallback := func() []kitSecret {
		out := make([]kitSecret, len(found))
		for i, f := range found {
			out[i] = kitSecret{secret: f}
		}
		return out
	}
	if len(found) == 0 || strings.Contains(s, "•") {
		return fallback()
	}
	parts := strings.Split(red, bullets)
	n := len(parts) - 1 // one value ends at each run of bullets
	if n < len(found) || !strings.HasPrefix(s, parts[0]) || !strings.HasSuffix(s, parts[n]) {
		return fallback()
	}
	out := make([]kitSecret, 0, n)
	pos := len(parts[0])
	next := 0 // the first entry of found no value has used yet
	for k := range n {
		// The hidden rest of value k runs from pos to where the text
		// after it starts: the first match for a middle value, the
		// suffix for the last one.
		after := parts[k+1]
		var end int
		if k == n-1 {
			end = len(s) - len(after)
		} else {
			if after == "" {
				return fallback()
			}
			i := strings.Index(s[min(pos+1, len(s)):], after)
			if i < 0 {
				return fallback()
			}
			end = pos + 1 + i
		}
		if end <= pos {
			return fallback()
		}
		i := matchFound(found, next, parts[k], n-k)
		if i < 0 {
			return fallback()
		}
		if i == next {
			next++
		}
		out = append(out, kitSecret{found[i], s[pos:end]})
		pos = end + len(after)
	}
	if next != len(found) {
		return fallback()
	}
	return out
}

// matchFound picks the entry of found that a value belongs to. before is
// the redacted text from the previous value up to this one's bullets, so
// it ends with the value's visible characters and usually holds its name.
// found lists each secret where it first shows, so a value is either one
// already seen (index below next) or found[next]. left is how many values
// remain, this one included. It returns -1 when none fits.
func matchFound(found []Secret, next int, before string, left int) int {
	score := func(i int) int {
		f := found[i]
		vis := strings.TrimSuffix(f.Masked, bullets)
		if !strings.HasSuffix(before, vis) {
			return -1
		}
		sc := 2 * len(vis)
		if f.Name != "" && strings.Contains(before, f.Name) {
			sc++
		}
		return sc
	}
	if next < len(found) && len(found)-next >= left {
		// Every remaining value must be a new entry.
		if score(next) < 0 {
			return -1
		}
		return next
	}
	best, bestScore := -1, -1
	for i := range next {
		if sc := score(i); sc > bestScore {
			best, bestScore = i, sc
		}
	}
	// A new entry wins a tie: it has to show up somewhere.
	if next < len(found) {
		if sc := score(next); sc >= 0 && sc >= bestScore {
			return next
		}
	}
	return best
}

// Redact replaces every secret value in s with its masked form.
func Redact(s string) string {
	return redactExtra(secrets.Redact(s))
}

// Mask keeps at most keep leading characters and hides the rest. The
// number of bullets is fixed so the length of the secret does not leak.
func Mask(v string, keep int) string {
	return CleanText(secrets.Mask(v, keep))
}

// SecretRules lists every rule FindSecrets applies: the kit catalog in
// the order the kit applies it, then the Tuner supplement. The ID is the
// Kind of the secrets a rule finds; several rules can share one.
func SecretRules() []secrets.RuleInfo {
	return append(secrets.Rules(), supplementRules...)
}

// The Tuner supplement as rule listings (see secrets_extra.go).
var supplementRules = []secrets.RuleInfo{
	{ID: "env", Description: "Env name run together with PW or KEYS (dbpw, LICENSEKEYS)", Tags: []string{"config", "tuner"}},
	{ID: "composer-auth", Description: "Token in composer auth.json (github-oauth, gitlab-oauth, gitlab-token, bearer)", Tags: []string{"config", "packages", "tuner"}},
}

// Labels for kinds whose rule description doesn't shorten well: shapes
// that no single provider owns.
var labelOverrides = map[string]string{ //nolint:gosec // G101: labels for secret kinds, no credentials
	"brevo-key": "Brevo key", "github-fine-grained-token": "GitHub fine-grained token", "private-key": "private key", "url-credentials": "URL password",
	"authorization": "Authorization header", "cookie": "cookie", "header-token": "token header",
	"wp-reset-key": "reset key", "oauth-code": "OAuth code", "key-path-token": "path token",
	"reset-link-token": "reset link token", "wp-config": "wp-config.php secret",
	"php-serialized": "plugin option", "npmrc-auth": "npm credential", "curl-user": "curl password",
	"env": "env secret", "yaml": "YAML secret", "json-field": "JSON secret", "assignment": "code secret",
	"form-field": "form secret", "composer-auth": "Composer token",
}

// secretLabels names each kind briefly for finding titles, from the rule
// descriptions: "OpenAI API key" reads "OpenAI key".
var secretLabels = func() map[string]string {
	m := map[string]string{}
	for _, r := range SecretRules() {
		if _, ok := m[r.ID]; !ok {
			m[r.ID] = cmp.Or(labelOverrides[r.ID], shortLabel(r.Description))
		}
	}
	return m
}()

// shortLabel cuts a rule description to the provider and what it holds:
// "Slack bot, user or workspace token" reads "Slack token".
func shortLabel(desc string) string {
	d := strings.ReplaceAll(desc, " API", "")
	for _, cut := range []string{" next to", " in a ", " (", ", bare"} {
		if i := strings.Index(d, cut); i > 0 {
			d = d[:i]
		}
	}
	if strings.Contains(d, " or ") || strings.Contains(d, ", ") {
		w := strings.Fields(strings.NewReplacer(",", "").Replace(d))
		d = w[0] + " " + w[len(w)-1]
	}
	return d
}

// maxTitleSecrets is how many secrets a finding title names before it
// says how many more there are.
const maxTitleSecrets = 3

// SecretSummary describes masked secrets for a finding title, such as
// "2 secrets (OpenAI key sk-p•••••, DB_PASSWORD=su•••••)". A secret with
// a name shows as name=masked, one without as its kind's label and the
// masked value. It returns "" for none.
func SecretSummary(found []Secret) string {
	if len(found) == 0 {
		return ""
	}
	var parts []string
	for i, s := range found {
		if i == maxTitleSecrets {
			parts = append(parts, fmt.Sprintf("%d more", len(found)-i))
			break
		}
		label, ok := secretLabels[s.Kind]
		switch {
		case s.Name != "" || !ok:
			parts = append(parts, s.String())
		default:
			parts = append(parts, label+" "+s.Masked)
		}
	}
	noun := "secrets"
	if len(found) == 1 {
		noun = "secret"
	}
	return fmt.Sprintf("%d %s (%s)", len(found), noun, strings.Join(parts, ", "))
}

// TitleWithSecrets appends SecretSummary to a finding title, as in
// "WordPress debug.log exposed: 2 secrets (OpenAI key sk-p•••••, Mailgun
// key key-•••••)". With no secrets it returns title unchanged.
func TitleWithSecrets(title string, found []Secret) string {
	if s := SecretSummary(found); s != "" {
		return title + ": " + s
	}
	return title
}
