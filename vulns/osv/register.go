// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package osv

import (
	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/vulns"
)

// The Composer rules go into the engine's registry, like the advisor's.
func init() { engine.RegisterRules("osv", vulns.EngineRules(Rules())...) }
