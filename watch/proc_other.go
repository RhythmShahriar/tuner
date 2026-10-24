// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix && !windows

package watch

import "os/exec"

// detach does nothing where there are no process groups.
func detach(*exec.Cmd) {}
