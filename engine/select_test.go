// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"errors"
	"slices"
	"testing"
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
	// Fallback rules stand in for vulns and local until they register.
	if r, ok := RuleFor("vuln-plugin-akismet"); !ok || r.ID != "vuln" {
		t.Errorf("fallback: %+v %v", r, ok)
	}
	if slices.ContainsFunc(Rules(), func(r Rule) bool { return r.ID == "wp-core-" }) {
		t.Error("fallback rules must stay out of Rules")
	}
}
