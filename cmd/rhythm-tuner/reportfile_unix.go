// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
)

// processUmask is the umask Tuner started with. It is read once at
// start, before any goroutine could create a file under the brief zero
// umask the read needs.
var processUmask = readUmask()

// readUmask returns the process umask. Setting it is the only way to
// read it, so it is set to 0 and back.
func readUmask() os.FileMode {
	m := syscall.Umask(0)
	syscall.Umask(m)
	return os.FileMode(m) & os.ModePerm //nolint:gosec // a umask fits in 9 bits
}

// mayFollow reports whether the kernel's fs.protected_symlinks rule lets
// this process follow the symlink at link (fi is its Lstat): always
// outside a sticky, world-writable folder; inside one only when the link
// is ours or the folder owner's.
func mayFollow(link string, fi os.FileInfo) bool {
	ls, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	dfi, err := os.Stat(filepath.Dir(link))
	if err != nil {
		return false
	}
	ds, ok := dfi.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	shared := dfi.Mode()&os.ModeSticky != 0 && dfi.Mode().Perm()&0o002 != 0
	return followAllowed(shared, ls.Uid, ds.Uid, uint32(os.Geteuid())) //nolint:gosec // uids are never negative
}

// followAllowed is the protected_symlinks rule: a link in a shared
// (sticky, world-writable) folder is followed only by its owner, or when
// the folder's owner made it.
func followAllowed(shared bool, linkUID, dirUID, me uint32) bool {
	return !shared || linkUID == me || linkUID == dirUID
}
