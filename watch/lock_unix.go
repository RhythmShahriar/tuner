// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package watch

import (
	"errors"
	"os"
	"syscall"
)

// lockFile opens path and takes an exclusive flock on it. flock belongs
// to the open file, so a second open in the same process conflicts too.
func lockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // the watch's own state folder
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // Fd fits an int on every unix
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return f, nil
}

// releaseLock does nothing: closing the file released the OS lock, and
// the file stays so the next run locks the same one.
func releaseLock(string) {}
