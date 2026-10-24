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

// The values that leaked in clear before Tuner used kit/secrets, plus one
// positive case for every supplement rule. Each case names the raw secret
// that must never show and the kind the finding must carry.
func TestFindSecretsKitAndSupplement(t *testing.T) {
	cases := []struct{ in, secret, kind string }{
		// Repro values from the October 2026 review.
		{"SLACK=https://hooks.slack.com/services/T0000AAAA/B0000BBBB/abcdefghijklmnopqrstuvwx\n", "abcdefghijklmnopqrstuvwx", "slack-webhook"},
		{"REDIS_URL=redis://:S3cretRedisPass@cache:6379/0\n", "S3cretRedisPass", "url-credentials"},
		{"MYSQL_PWD=myS3cretPw\n", "myS3cretPw", "env"},
		{"DB_PWD=dbS3cretPw\n", "dbS3cretPw", "env"},
		{"APIKEY=abcdef123456\n", "abcdef123456", "header-token"},
		{`{"http-basic": {"repo.example.com": {"username": "bob", "password": "Bas1cPassw0rd"}}}`, "Bas1cPassw0rd", "json-field"},
		// Former supplement rules that kit/secrets v0.6 now covers.
		{"SMTP_PW=smtpS3cret\n", "smtpS3cret", "env"},
		{"LICENSEKEY=lic-0123456789\n", "lic-0123456789", "env"},
		{"STRIPE_SECRETKEYS=sec-0123456789\n", "sec-0123456789", "env"},
		{"SENTRY_DSN=pub0123456789abcdef\n", "pub0123456789abcdef", "env"},
		{"AWS_CREDENTIALS=credS3cretValue\n", "credS3cretValue", "env"},
		{"smtp_credential='credS3cret2'\n", "credS3cret2", "env"},
		{"mysqlpwd=pwdS3cretValue\n", "pwdS3cretValue", "env"},
		{"amqp://:Rabb1tPass@mq:5672", "Rabb1tPass", "url-credentials"},
		{`{"bitbucket-oauth": {"bitbucket.org": {"consumer-key": "consumerKeyValue", "consumer-secret": "consumerSecretValue"}}}`, "consumerKeyValue", "json-field"},
		// Rules the Tuner supplement still adds.
		{"export dbpw=lowerS3cret\n", "lowerS3cret", "env"},
		{"DBPW=upperS3cret\n", "upperS3cret", "env"},
		{"LICENSEKEYS=lic-0123456789\n", "lic-0123456789", "env"},
		{`{"github-oauth": {"github.com": "oauthT0kenValue123"}}`, "oauthT0kenValue123", "composer-auth"},
		{`{"gitlab-oauth": {"gitlab.com": "glOauthValue123"}}`, "glOauthValue123", "composer-auth"},
		{`{"gitlab-token": {"gitlab.com": "glT0kenValue123"}}`, "glT0kenValue123", "composer-auth"},
		{`{"bearer": {"repo.example.org": "bearerT0kenValue"}}`, "bearerT0kenValue", "composer-auth"},
	}
	for _, c := range cases {
		got := FindSecrets([]byte(c.in))
		kinds := map[string]bool{}
		for _, s := range got {
			kinds[s.Kind] = true
			if strings.Contains(s.String(), c.secret) {
				t.Errorf("%q: masked output %q leaks the secret", c.in, s)
			}
		}
		if !kinds[c.kind] {
			t.Errorf("%q: kinds %v, want %s", c.in, got, c.kind)
		}
		if red := Redact(c.in); strings.Contains(red, c.secret) {
			t.Errorf("Redact(%q) = %q leaks the secret", c.in, red)
		}
	}
}

// Lines the supplement must leave alone.
func TestFindSecretsSupplementNegatives(t *testing.T) {
	for _, in := range []string{
		"KEYBOARD_LAYOUT=us-international\n",
		"HOTKEY=ctrl-shift-k\n",
		"HOTKEYS=ctrl-shift-k\n",
		"MONKEYS=twelve\n",
		"PWA_NAME=Shop\n",
		"CREDENTIALS_FILE=./creds.json\n",
		"MYSQL_PWD=${MYSQL_PWD}\n",
		"DB_PWD=null\n",
		"DBPW=${DBPW}\n",
		"see https://example.com/:path@x",
		`{"github-oauth": {}}`,
	} {
		if got := FindSecrets([]byte(in)); len(got) != 0 {
			t.Errorf("%q: unexpected secrets %v", in, got)
		}
		if red := Redact(in); red != in {
			t.Errorf("Redact(%q) = %q, want unchanged", in, red)
		}
	}
}

// kit/secrets v0.6 masks these, which the old supplement left alone: a
// name part KEY anywhere, a credentials path and a short value under a
// secret name. Masking too much is the safe side, so Tuner follows the kit.
func TestFindSecretsKitMasksMore(t *testing.T) {
	for in, secret := range map[string]string{
		"KEY_REPEAT_DELAY=250ms\n":                               "250ms",
		"GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/service.json\n": "service.json",
		"DB_PW=xy\n": "xy",
	} {
		if got := FindSecrets([]byte(in)); len(got) != 1 {
			t.Errorf("%q: got %v, want one secret", in, got)
		}
		if red := Redact(in); strings.Contains(red, secret) {
			t.Errorf("Redact(%q) = %q leaks the value", in, red)
		}
	}
}

// A value both the kit and the supplement would catch is reported once.
func TestFindSecretsNoDoubleReport(t *testing.T) {
	got := FindSecrets([]byte("export GITHUB_DBPW=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"))
	if len(got) != 1 || got[0].Kind != "github-token" {
		t.Errorf("got %v, want one github-token", got)
	}
}

func TestMaskCleansControlBytes(t *testing.T) {
	if got := Mask("\x1b[31mred-secret", 3); strings.ContainsRune(got, 0x1b) {
		t.Errorf("Mask = %q keeps an escape byte", got)
	}
}
