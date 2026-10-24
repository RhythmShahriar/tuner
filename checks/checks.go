// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package checks embeds the built-in YAML checks and their fixtures.
// See https://github.com/RhythmShahriar/rhythm/wiki/Tuner-Writing-Checks for the format.
package checks

import "embed"

//go:embed */*.yaml
var FS embed.FS
