// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package local

import "github.com/RhythmShahriar/tuner/engine"

// localPrefix covers local finding IDs the catalog doesn't list, such as
// a rule a check pack adds: they still select, explain and link as local
// findings.
var localPrefix = engine.Rule{
	ID: "local-", Prefix: true, Title: "Local scan finding", Tags: []string{"local"},
	Severity: engine.Medium, HelpURI: HelpBase + "local-findings",
}

// Every local finding ID goes into the engine's registry, so selection
// by ID or tag, rhythm tuner explain and SARIF know them.
func init() {
	cat := Catalog()
	rules := make([]engine.Rule, 0, len(cat)+1)
	for _, r := range cat {
		rules = append(rules, engine.Rule(r))
	}
	engine.RegisterRules("local", append(rules, localPrefix)...)
}
