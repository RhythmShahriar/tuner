// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package local

import (
	"os"
	"syscall"
)

// openRead opens path for reading without blocking. Opening a FIFO
// normally waits for a writer, forever and past any deadline; with
// O_NONBLOCK it returns at once and the caller's Stat rejects it.
func openRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // reading the user's own site files is the point of a local scan
}
