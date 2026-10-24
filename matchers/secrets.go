// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package matchers

import (
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
