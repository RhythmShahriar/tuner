// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package matchers_test

import (
	"io/fs"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/tuner/checks"
	"github.com/RhythmShahriar/tuner/matchers"
)

// fixtureBody returns the body a positive case of a built-in check's
// fixture serves on path.
func fixtureBody(t *testing.T, file, name, path string) string {
	t.Helper()
	b, err := fs.ReadFile(checks.FS, file)
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Positive []struct {
			Name   string `yaml:"name"`
			Routes map[string]struct {
				Body string `yaml:"body"`
			} `yaml:"routes"`
		} `yaml:"positive"`
	}
	if err := yaml.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	for _, c := range fx.Positive {
		if c.Name == name {
			if r, ok := c.Routes[path]; ok {
				return r.Body
			}
		}
	}
	t.Fatalf("%s: no positive case %q serving %s", file, name, path)
	return ""
}

// The web-exposure fixtures added with the kit v0.6 catalog: what each
// one must find by kind and the title summary it gives.
func TestCatalogueOnFixtures(t *testing.T) {
	cases := []struct {
		file, name, path string
		kinds            []string
		summary          string
		raw              []string
	}{
		{"wordpress/debug-log_test.yaml", "openai and mailgun keys in plugin errors", "/wp-content/debug.log",
			[]string{"openai-key", "mailgun-key"}, "2 secrets (OpenAI key sk-p•••••, Mailgun key key-•••••)",
			[]string{"sk-proj-FAKEfake", "0123456789abcdef0123"}},
		{"wordpress/debug-log_test.yaml", "backup plugin s3 settings logged as json", "/wp-content/debug.log",
			[]string{"aws-access-key", "json-field"}, "",
			[]string{"IOSFODNN7EXAMPLE", "K7MDENG/bPxRfiCYEXAMPLEKEY"}},
		{"wordpress/debug-log-moved_test.yaml", "openai and mailgun keys in an uploads log", "/wp-content/uploads/debug.log",
			[]string{"openai-key", "mailgun-key"}, "", []string{"sk-proj-FAKEfake"}},
		{"leaks/wp-config-copy_test.yaml", "backup with wp mail smtp constants", "/wp-config.php.backup",
			[]string{"wp-config", "mailgun-key", "sendgrid-key"}, "",
			[]string{"smtp-relay-Pass-2026", "0123456789abcdef0123", "fakeFAKEfakeFAKE01"}},
		{"leaks/sql-dump_test.yaml", "dump with post smtp, wp mail smtp and updraftplus s3 options", "/wp.sql",
			[]string{"php-serialized", "mailgun-key", "aws-access-key"}, "",
			[]string{"PostSmtpPass2026", "WpMailSmtpPass2026", "IOSFODNN7EXAMPLE", "K7MDENG/bPxRfiCYEXAMPLEKEY"}},
		{"leaks/dotenv_test.yaml", "stripe live keys", "/.env",
			[]string{"stripe-key", "stripe-webhook-secret"}, "",
			[]string{"abcdefghijklmnop1234", "abcdefghijklmnop5678", "abcdefghijklmnop9012"}},
		{"leaks/dotenv_test.yaml", "openai and mailgun keys", "/.env",
			[]string{"openai-key", "mailgun-key"}, "2 secrets (OpenAI key sk-p•••••, Mailgun key key-•••••)", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := fixtureBody(t, c.file, c.name, c.path)
			got := matchers.FindSecrets([]byte(body))
			var kinds []string
			for _, s := range got {
				kinds = append(kinds, s.Kind)
			}
			for _, k := range c.kinds {
				if !slices.Contains(kinds, k) {
					t.Errorf("kinds %v, want %s", kinds, k)
				}
			}
			summary := matchers.SecretSummary(got)
			if c.summary != "" && summary != c.summary {
				t.Errorf("summary %q, want %q", summary, c.summary)
			}
			red := matchers.Redact(body)
			for _, r := range c.raw {
				if strings.Contains(summary, r) || strings.Contains(red, r) {
					t.Errorf("%q shows in the summary %q or the redacted body", r, summary)
				}
			}
		})
	}
}

// Look-alikes the catalog must not report: too short for the format,
// the wrong alphabet or a public key.
func TestCatalogueNegatives(t *testing.T) {
	for _, in := range []string{
		"PHP Notice: see https://platform.openai.com/docs for sk- keys\n",
		"PHP Notice: mailgun key-notahexvalue in send.php\n",
		"PHP Notice: AKIA1234 is too short\n",
		`{"service":"s3","path":"site-backups","region":"eu-west-1"}`,
		"var stripe = Stripe('pk_live_abcdefghijklmnop1234');\n", // publishable, meant for browsers
		"INSERT INTO `wp_options` VALUES (1,'blogname','a:1:{s:4:\"name\";s:4:\"Shop\";}','yes');\n",
	} {
		if got := matchers.FindSecrets([]byte(in)); len(got) != 0 {
			t.Errorf("%q: unexpected secrets %v", in, got)
		}
	}
}
