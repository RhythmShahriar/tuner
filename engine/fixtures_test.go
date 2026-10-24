// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package engine_test

import (
	"testing"

	"github.com/RhythmShahriar/tuner/checks"
	"github.com/RhythmShahriar/tuner/engine/checktest"
)

// Every built-in check must pass its positive and negative fixtures and
// render them safely in every report format.
func TestCheckFixtures(t *testing.T) {
	checktest.Test(t, checks.FS)
}
