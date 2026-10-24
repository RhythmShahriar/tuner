// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A debug.log with an OpenAI and a Mailgun key: every output names both
// in the finding title, masked. None shows the keys.
func TestSecretTitleInEveryFormat(t *testing.T) {
	const log = "[23-Oct-2026 10:00:00 UTC] PHP Warning:  OpenAI request failed with key sk-proj-FAKEfakeFAKEfake0123456789\n" +
		"[23-Oct-2026 10:00:02 UTC] PHP Notice:  Mailgun send failed for key-0123456789abcdef0123456789abcdef\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-content/debug.log" {
			_, _ = w.Write([]byte(log))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	const title = "WordPress debug.log exposed: 2 secrets (OpenAI key sk-p•••••, Mailgun key key-•••••)"
	for _, format := range []string{"--plain", "--json", "--md", "--sarif"} {
		code, out, errs := tuner(t, "scan", srv.URL, format, "--id", "wp-debug-log", "--no-vulns")
		if code != exitOK {
			t.Fatalf("%s: exit %d\n%s", format, code, errs)
		}
		want := title
		if format == "--md" {
			want = strings.NewReplacer("(", `\(`, ")", `\)`).Replace(title)
		}
		if !strings.Contains(out, want) {
			t.Errorf("%s: no %q in\n%s", format, want, out)
		}
		for _, raw := range []string{"FAKEfakeFAKEfake", "0123456789abcdef0123"} {
			if strings.Contains(out, raw) {
				t.Errorf("%s: output shows %q", format, raw)
			}
		}
	}
}

func TestChecksTagsSecretsListsRules(t *testing.T) {
	code, out, _ := tuner(t, "checks", "--tags", "secrets", "--no-check-updates")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{"wp-debug-log ", "leak-dotenv ", "\nSecret rules (", "openai-key ", "OpenAI API key", "mailgun-key ", "composer-auth "} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if _, out, _ := tuner(t, "checks", "--tags", "wordpress", "--no-check-updates"); strings.Contains(out, "Secret rules") {
		t.Error("checks without --tags secrets listed the secret rules")
	}
}

// A .env with two OpenAI and two Stripe live keys: the title counts four
// secrets although each pair masks alike.
func TestSecretTitleCountsDistinctKeys(t *testing.T) {
	const env = "OPENAI_API_KEY=sk-proj-FAKEfakeFAKEfake0123456789\n" +
		"OPENAI_BACKUP_KEY=sk-proj-OTHERotherOTHERother987654\n" +
		"STRIPE_SECRET=sk_live_abcdefghijklmnop1234\n" +
		"STRIPE_OLD_SECRET=sk_live_zyxwvutsrqponmlk9876\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			_, _ = w.Write([]byte(env))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	code, out, errs := tuner(t, "scan", srv.URL, "--plain", "--id", "leak-dotenv", "--no-vulns")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	if want := ".env file exposed: 4 secrets"; !strings.Contains(out, want) {
		t.Errorf("no %q in\n%s", want, out)
	}
	for _, raw := range []string{"FAKEfake", "OTHERother", "abcdefgh", "zyxwvuts"} {
		if strings.Contains(out, raw) {
			t.Errorf("output shows %q", raw)
		}
	}
}
