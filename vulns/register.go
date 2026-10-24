// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package vulns

import "github.com/RhythmShahriar/tuner/engine"

// The advisor's rules go into the engine's registry, so selection by ID
// or tag, rhythm tuner explain and SARIF know every finding it emits.
func init() { engine.RegisterRules("vulns", EngineRules(Rules())...) }

// EngineRules converts rules for engine.RegisterRules.
func EngineRules(rs []Rule) []engine.Rule {
	out := make([]engine.Rule, len(rs))
	for i, r := range rs {
		out[i] = engine.Rule(r)
	}
	return out
}
