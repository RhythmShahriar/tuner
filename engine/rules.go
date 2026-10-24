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
// init(). Registering a source again adds to what it already has.
func RegisterRules(source string, rs ...Rule) {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	rules[source] = append(rules[source], rs...)
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
