// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

func TestRuleMatches(t *testing.T) {
	plugin := NewRule("vuln-plugin-", true, engine.High, "Plugin", "vuln")
	core := NewRule("vuln-core", false, engine.High, "Core", "vuln")
	for _, c := range []struct {
		r    Rule
		id   string
		want bool
	}{
		{plugin, "vuln-plugin-akismet", true},
		{plugin, "vuln-plugin-", false},
		{plugin, "vuln-theme-x", false},
		{core, "vuln-core", true},
		{core, "vuln-core-x", false},
	} {
		if got := c.r.Matches(c.id); got != c.want {
			t.Errorf("%s matches %s = %v", c.r.ID, c.id, got)
		}
	}
	if plugin.HelpURI != HelpBase+"vuln-plugin" || core.HelpURI != HelpBase+"vuln-core" {
		t.Errorf("help: %s, %s", plugin.HelpURI, core.HelpURI)
	}
}

// Every ID the advisor emits, across fixtures that reach each kind of
// finding, has a rule; and every rule is reached by some fixture.
func TestEveryFindingHasARule(t *testing.T) {
	f := newFakeAPI(t, map[string]string{
		"/theme/twentyten/":        `{"error":0,"data":{"name":"Twenty Ten","closed":1,"vulnerability":[{"uuid":"t1","name":"Twenty Ten < 4.0","operator":{"max_version":"4.0","max_operator":"lt","unfixed":"0"},"source":[],"impact":{}}]}}`,
		"/apache/2.2.34/":          `{"error":0,"data":{"apache":"2.2.34","name":"Apache 2.2","date_end":"2017-07-01","vulnerability":[{"uuid":"a1","name":"Apache < 2.4","operator":{"max_version":"2.4.0","max_operator":"lt","unfixed":"0"},"source":[],"impact":{}}]}}`,
		"/nginx/1.0.0/":            `{"error":0,"data":{"nginx":"1.0.0","name":"nginx 1.0","date_end":"2012-04-01","vulnerability":[{"uuid":"n1","name":"nginx < 1.2","operator":{"max_version":"1.2.0","max_operator":"lt","unfixed":"0"},"source":[],"impact":{}}]}}`,
		"/core/7.0/":               `{"error":0,"data":{"vulnerability":[]}}`,
		"/core/version-check/1.7/": `{"offers":[{"current":"7.1.3"}]}`,
	})
	fixtures := []fingerprint.Result{
		{
			Tech: []string{"wordpress", "php"}, WordPress: "6.4.1", PHP: "7.4.3", Server: "nginx/1.25.3",
			Components: []fingerprint.Component{
				{Type: "plugin", Slug: "contact-form-7", Version: "5.3.1"},
				{Type: "plugin", Slug: "old-gallery", Version: "1.0"},
				{Type: "plugin", Slug: "no-version"},
				{Type: "plugin", Slug: "akismet", Version: "5.0"},
				{Type: "theme", Slug: "twentyten", Version: "3.0"},
			},
		},
		{Tech: []string{"wordpress", "php"}, WordPress: "7.0", Server: "Apache/2.2.34 (Ubuntu)"},
		{Server: "nginx/1.0.0"},
		{Tech: []string{"php"}, PHP: "8.1.2"},
	}
	emitted := map[string]bool{}
	rules := Rules()
	for _, fp := range fixtures {
		findings, _ := newAdvisor(f, t.TempDir()).Advise(context.Background(), base, fp)
		for _, x := range findings {
			emitted[x.ID] = true
			r, ok := RuleFor(rules, x.ID)
			if !ok {
				t.Errorf("%s has no rule", x.ID)
				continue
			}
			if !slices.ContainsFunc(r.Tags, func(tag string) bool { return slices.Contains(x.Tags, tag) }) {
				t.Errorf("%s: rule tags %v share nothing with the finding's %v", x.ID, r.Tags, x.Tags)
			}
		}
	}
	for _, r := range rules {
		if !strings.HasPrefix(r.HelpURI, HelpBase) || r.Title == "" || r.Severity.Rank() < 0 {
			t.Errorf("rule %+v incomplete", r)
		}
		if !slices.ContainsFunc(keysOf(emitted), r.Matches) {
			t.Errorf("no fixture reaches rule %s", r.ID)
		}
	}
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
