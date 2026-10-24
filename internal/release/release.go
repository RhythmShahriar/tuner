// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// Package release names Tuner's releases: the repository the release
// workflow runs in and the binary its archives carry. A valid signature on
// a release's checksums.txt names this repository and the release tag;
// package signature checks it.
//
// It imports nothing, so the rhythm-tuner binary can use the names
// without linking the Sigstore libraries.
package release

// Tuner's release repository and binary name.
const (
	Repo   = "RhythmShahriar/tuner"
	Binary = "rhythm-tuner"
)
