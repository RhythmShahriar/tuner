// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix && !windows

package watch

import (
	"errors"
	"os"
)

// lockFile creates path exclusively. Without an OS file lock a crash
// leaves the file behind; deleting it by hand frees the watch.
func lockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil, ErrLocked
	}
	if err != nil {
		return nil, err
	}
	return f, nil
}

// releaseLock deletes the lock file, which is the lock here.
func releaseLock(path string) { _ = os.Remove(path) }
