// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import (
	"strings"

	"github.com/RhythmShahriar/tuner/engine"
)

// HelpBase is where each finding is explained: the ID is the anchor.
const HelpBase = "https://github.com/RhythmShahriar/rhythm/wiki/Tuner-Finding-Reference#"

// Rule describes the findings with one ID, or with every ID that starts
// with it when Prefix is set (vuln-plugin- covers vuln-plugin-akismet).
// It has the fields of engine.Rule, so the engine's rule registry can take
// these as they are.
type Rule struct {
	ID       string
	Prefix   bool
	Title    string
	Tags     []string
	Severity engine.Severity // the usual severity; vulnerability findings take their worst advisory's
	HelpURI  string
}

// Matches reports whether the finding ID id is one of r's.
func (r Rule) Matches(id string) bool {
	if r.Prefix {
		return strings.HasPrefix(id, r.ID) && len(id) > len(r.ID)
	}
	return id == r.ID
}

// RuleFor returns the rule in rules that describes the finding ID id.
func RuleFor(rules []Rule, id string) (Rule, bool) {
	for _, r := range rules {
		if r.Matches(id) {
			return r, true
		}
	}
	return Rule{}, false
}

// NewRule builds a Rule whose help is the Finding Reference entry for
// its ID (without the trailing "-" of a prefix).
func NewRule(id string, prefix bool, sev engine.Severity, title string, tags ...string) Rule {
	return Rule{ID: id, Prefix: prefix, Title: title, Tags: tags, Severity: sev, HelpURI: HelpBase + strings.TrimSuffix(id, "-")}
}
