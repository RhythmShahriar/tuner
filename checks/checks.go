// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package checks embeds the built-in YAML checks and their fixtures.
// See https://github.com/RhythmShahriar/rhythm/wiki/Tuner-Writing-Checks for the format.
package checks

import "embed"

// FS holds the checks and their _test.yaml fixtures, one folder per area
// (wordpress/, leaks/, tls/ and so on). Only YAML one folder down is
// embedded, so pack.json at the root stays out of the check set.
//
//go:embed */*.yaml
var FS embed.FS

// License is the MIT license the checks are published under, for exports
// that ship checks outside this repository.
//
//go:embed LICENSE
var License string
