// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"slices"
	"strings"
	"sync"
)

// Rule describes a finding ID that Go code emits rather than a YAML check,
// e.g. vuln-plugin-* from the vulnerability advisor or local-* from local
// scans. Selection, listings and SARIF use the registry to know them.
type Rule struct {
	ID       string   // finding ID, or its prefix when Prefix is set
	Prefix   bool     // ID is a prefix: vuln-plugin- covers vuln-plugin-akismet
	Title    string   // short description for listings
	Tags     []string // tags --tags can select on
	Severity Severity // usual severity; findings may differ
	HelpURI  string   // where the rule is documented
}

var (
	rulesMu sync.Mutex
	rules   = map[string][]Rule{} // by source, e.g. "vulns" or "local"
)

// RegisterRules records the rules a source emits. Sources call it from
// init(). Registering a source again adds to what it already has; a rule
// whose ID the source already registered replaces the old one, so a
// source that registers twice still lists each rule once.
func RegisterRules(source string, rs ...Rule) {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	have := rules[source]
	for _, r := range rs {
		if i := slices.IndexFunc(have, func(o Rule) bool { return o.ID == r.ID }); i >= 0 {
			have[i] = r
			continue
		}
		have = append(have, r)
	}
	rules[source] = have
}

// Rules returns every registered rule, sorted by ID.
func Rules() []Rule {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	var out []Rule
	for _, rs := range rules {
		out = append(out, rs...)
	}
	slices.SortStableFunc(out, func(a, b Rule) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Matches reports whether finding ID id belongs to r.
func (r Rule) Matches(id string) bool {
	if r.Prefix {
		return strings.HasPrefix(id, r.ID)
	}
	return id == r.ID
}

// mayMatch reports whether an ID glob such as vuln-* can match a finding
// of r. A prefix rule matches when the glob's literal start and the prefix
// agree as far as both go; "*" alone matches nothing, so it never turns
// advisors on by itself.
func (r Rule) mayMatch(pattern string) bool {
	i := strings.IndexAny(pattern, "*?[")
	if i < 0 {
		return r.Matches(pattern)
	}
	lit := pattern[:i]
	if lit == "" {
		return false
	}
	if r.Prefix {
		return strings.HasPrefix(lit, r.ID) || strings.HasPrefix(r.ID, lit)
	}
	return globMatch(pattern, r.ID)
}

// RuleFor returns the registered rule a finding ID belongs to: an exact
// rule first, else the longest matching prefix rule.
func RuleFor(id string) (Rule, bool) {
	var best Rule
	found := false
	for _, r := range Rules() {
		switch {
		case !r.Matches(id):
		case !r.Prefix:
			return r, true
		case !found || len(r.ID) > len(best.ID):
			best, found = r, true
		}
	}
	return best, found
}

// AdvisorTags returns every tag a rule declares, sorted: the tags --tags
// can select advisor findings by.
func AdvisorTags() []string {
	var tags []string
	for _, r := range Rules() {
		for _, t := range r.Tags {
			if !slices.Contains(tags, t) {
				tags = append(tags, t)
			}
		}
	}
	slices.Sort(tags)
	return tags
}
