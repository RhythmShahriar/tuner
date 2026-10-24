// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package local

import "os"

// openRead opens path for reading. Windows has no FIFOs in the file
// system, so a plain open can't block the way it can on unix.
func openRead(path string) (*os.File, error) {
	return os.Open(path) //nolint:gosec // reading the user's own site files is the point of a local scan
}
