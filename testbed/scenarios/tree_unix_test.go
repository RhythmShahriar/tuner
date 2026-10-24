// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package scenarios

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

func mkfifo(p string) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return syscall.Mkfifo(p, 0o644)
}

// listenUnix binds a socket at p. Socket paths are limited to about 100
// bytes and test folders are often deeper, so it binds in a short temp
// folder and renames the socket into place; the listener stays bound.
func listenUnix(p string) (io.Closer, error) {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, err
	}
	short, err := os.MkdirTemp("", "ts")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(short) }()
	tmp := filepath.Join(short, "s")
	if len(tmp) > 100 {
		return nil, fmt.Errorf("socket path %s is too long", tmp)
	}
	l, err := net.Listen("unix", tmp)
	if err != nil {
		return nil, err
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := os.Rename(tmp, p); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

func sendSignal(p *os.Process, name string) error {
	switch name {
	case "INT":
		return p.Signal(os.Interrupt)
	case "TERM":
		return p.Signal(syscall.SIGTERM)
	case "KILL":
		return p.Kill()
	}
	return fmt.Errorf("unknown signal %q", name)
}
