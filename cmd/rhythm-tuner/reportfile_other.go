// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package main

import "os"

// processUmask is 022. There is no umask outside Unix, where a mode only
// sets the read-only flag.
const processUmask os.FileMode = 0o022

// mayFollow lets every link be followed: shared sticky folders are a
// Unix thing.
func mayFollow(string, os.FileInfo) bool { return true }
