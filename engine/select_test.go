// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"testing"

	"github.com/RhythmShahriar/tuner/fingerprint"
)

// A provider that registers its rules gets its IDs and tags accepted
// without engine changes.
func TestRegistryDrivesSelection(t *testing.T) {
	restoreRules(t)
	RegisterRules("acme", Rule{ID: "acme-", Prefix: true, Title: "Acme advisories", Tags: []string{"acme"}, Severity: High},
		Rule{ID: "acme-special", Title: "Acme special", Tags: []string{"acme", "special"}})
	all := []*Check{mustParse(t, "id: leak-dotenv\nname: env\nseverity: high\nrequest: {path: [/.env]}\nmatch: {all: [{status: 200}]}")}

	// --id acme-x is an advisor ID: no "no check matches" error, only no
	// YAML checks to run.
	if _, err := Select(all, Selector{IDs: []string{"acme-x"}}); !errors.Is(err, ErrNoChecks) {
		t.Errorf("acme-x: %v", err)
	}
	if _, err := Select(all, Selector{IDs: []string{"acme-*", "leak-dotenv"}}); err != nil {
		t.Errorf("acme-* with a check: %v", err)
	}
	if !IsAdvisorID("acme-x") || !IsAdvisorID("ac*") || IsAdvisorID("acm") {
		t.Error("IsAdvisorID ignores the registry")
	}
	// Unknown IDs still fail, with a suggestion when one is close.
	if _, err := Select(all, Selector{IDs: []string{"leak-dotnev"}}); err == nil || err.Error() != `no check matches "leak-dotnev"; did you mean "leak-dotenv"? list them with: rhythm tuner checks` {
		t.Errorf("leak-dotnev: %v", err)
	}
	if _, err := Select(all, Selector{IDs: []string{"nope"}}); err == nil || errors.Is(err, ErrNoChecks) {
		t.Errorf("nope: %v", err)
	}

	// --tags acme keeps advisors on: callers check AdvisorTags.
	tags := AdvisorTags()
	for _, want := range []string{"acme", "special", "vuln", "known-exploited", "outdated"} {
		if !slices.Contains(tags, want) {
			t.Errorf("AdvisorTags lacks %q: %v", want, tags)
		}
	}
	if !slices.IsSorted(tags) {
		t.Errorf("AdvisorTags not sorted: %v", tags)
	}

	if r, ok := RuleFor("acme-special"); !ok || r.Title != "Acme special" {
		t.Errorf("exact rule: %+v %v", r, ok)
	}
	if r, ok := RuleFor("acme-other"); !ok || r.Title != "Acme advisories" {
		t.Errorf("prefix rule: %+v %v", r, ok)
	}
	if _, ok := RuleFor("leak-dotenv"); ok {
		t.Error("a YAML check ID has no rule")
	}
	// Only registered rules exist: no built-in fallback list.
	if r, ok := RuleFor("vuln-plugin-akismet"); !ok || r.ID != "vuln-plugin-" {
		t.Errorf("registered prefix: %+v %v", r, ok)
	}
	if _, ok := RuleFor("nginx-eol"); ok {
		t.Error("a rule nobody registered matched")
	}
}

type statusOnly struct{ status string }

func (s statusOnly) Advise(ctx context.Context, base *url.URL, fp fingerprint.Result) ([]Finding, []string) {
	f, w, _ := s.AdviseStatus(ctx, base, fp)
	return f, w
}

func (s statusOnly) AdviseStatus(context.Context, *url.URL, fingerprint.Result) ([]Finding, []string, string) {
	return []Finding{{ID: "vuln-core", Severity: High}, {ID: "php-eol", Severity: Low}}, []string{"w"}, s.status
}

// Filtered keeps the advisor's data status visible through the filter.
func TestFilteredForwardsStatus(t *testing.T) {
	a := Filtered(statusOnly{"partial"}, Selector{MinSeverity: High})
	sa, ok := a.(StatusAdvisor)
	if !ok {
		t.Fatal("Filtered hides AdviseStatus")
	}
	findings, warnings, status := sa.AdviseStatus(context.Background(), &url.URL{}, fingerprint.Result{})
	if len(findings) != 1 || findings[0].ID != "vuln-core" || len(warnings) != 1 || status != "partial" {
		t.Errorf("%v %v %q", findings, warnings, status)
	}
	if !(Selector{IDs: []string{"vuln-*"}}).Keeps(Finding{ID: "vuln-core"}) || (Selector{ExcludeTags: []string{"x"}}).Keeps(Finding{ID: "a", Tags: []string{"x"}}) {
		t.Error("Keeps")
	}
}
