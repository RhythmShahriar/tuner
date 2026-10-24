// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package engine

import (
	"errors"
	"syscall"
)

// connRefused reports whether err is a refused TCP connection.
func connRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
