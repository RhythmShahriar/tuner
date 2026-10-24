// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package matchers

import (
	"cmp"
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
func FindSecrets(b []byte) []Secret {
	found := secrets.FindSecrets(b)
	out := make([]Secret, 0, len(found))
	seen := map[Secret]bool{}
	add := func(s Secret) {
		s.Masked = CleanText(s.Masked)
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range found {
		add(s)
	}
	for _, sp := range extraSpans(secrets.Redact(string(b))) {
		add(sp.secret)
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
