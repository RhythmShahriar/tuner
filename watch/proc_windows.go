// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package watch

import (
	"os/exec"
	"syscall"
)

// detach starts the scan in a new process group, so Ctrl-C in the
// watch's console reaches the watch alone and the scan can finish.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}
