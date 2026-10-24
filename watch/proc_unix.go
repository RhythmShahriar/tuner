// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package watch

import (
	"os/exec"
	"syscall"
)

// detach puts the scan in its own process group, so Ctrl-C in the
// watch's terminal reaches the watch alone: the watch then lets the
// scan finish (or interrupts it on a second Ctrl-C).
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
