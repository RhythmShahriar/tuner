// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package engine

import (
	"errors"
	"syscall"
)

// wsaeConnRefused is WSAECONNREFUSED. On Windows a refused dial carries
// this Winsock code; syscall.ECONNREFUSED there is a made-up value that
// no dial returns.
const wsaeConnRefused = syscall.Errno(10061)

// connRefused reports whether err is a refused TCP connection.
func connRefused(err error) bool {
	return errors.Is(err, wsaeConnRefused) || errors.Is(err, syscall.ECONNREFUSED)
}

// wsaeConnReset is WSAECONNRESET, the Winsock code of a reset connection.
const wsaeConnReset = syscall.Errno(10054)

// connReset reports whether err is a TCP connection the peer reset.
func connReset(err error) bool {
	return errors.Is(err, wsaeConnReset) || errors.Is(err, syscall.ECONNRESET)
}
