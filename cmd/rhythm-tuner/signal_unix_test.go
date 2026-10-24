// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package main

import (
	"os"
	"syscall"
)

// interruptSelf sends this process SIGINT, as Ctrl-C does.
func interruptSelf() { _ = syscall.Kill(os.Getpid(), syscall.SIGINT) }
