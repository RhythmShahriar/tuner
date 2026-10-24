// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package matchers

import (
	"strings"
	"testing"
)

func TestFindSecretsMasks(t *testing.T) {
	raw := map[string]string{
		"DB_PASSWORD=supersecret\n":                                   "supersecret",
		"STRIPE_KEY=sk_live_abcdefghijklmnop1234\n":                   "sk_live_abcdefghijklmnop1234",
		"key AKIAABCDEFGHIJKLMNOP here":                               "AKIAABCDEFGHIJKLMNOP",
		"define( 'DB_PASSWORD', 'wp-pass-123' );":                     "wp-pass-123",
		"DATABASE_URL=mysql://root:hunter22@db:3306/app":              "hunter22",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx1234567\n": "MIIEowIBAAKCAQEAx1234567",
	}
	for in, secret := range raw {
		got := FindSecrets([]byte(in))
		if len(got) == 0 {
			t.Errorf("%q: no secret found", in)
			continue
		}
		for _, s := range got {
			if strings.Contains(s.String(), secret) {
				t.Errorf("%q: masked output %q leaks the secret", in, s)
			}
		}
		if red := Redact(in); strings.Contains(red, secret) {
			t.Errorf("Redact(%q) = %q leaks the secret", in, red)
		}
	}
}

func TestFindSecretsSkipsPlaceholders(t *testing.T) {
	for _, in := range []string{"DB_PASSWORD=\n", "DB_PASSWORD=null\n", "API_KEY=${API_KEY}\n", "APP_NAME=Laravel\n"} {
		if got := FindSecrets([]byte(in)); len(got) != 0 {
			t.Errorf("%q: unexpected secrets %v", in, got)
		}
	}
}

func TestMask(t *testing.T) {
	if got := Mask("supersecret", 2); got != "su•••••" {
		t.Errorf("Mask = %q", got)
	}
	if got := Mask("abc", 8); got != "a•••••" {
		t.Errorf("short Mask = %q", got)
	}
}
