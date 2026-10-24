// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package local

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/fingerprint"
)

// A FIFO, socket or device where a site file belongs must not hang the
// scan: opening a FIFO with no writer blocks forever, past --max-time.
func TestSpecialFilesDontBlock(t *testing.T) {
	root := tree(t, map[string]string{
		"wp-includes/version.php":        "<?php $wp_version = '6.5';",
		"wp-content/themes/ok/style.css": "/*\nTheme Name: OK\nVersion: 1.0\n*/",
	})
	for _, d := range []string{"sock", "zero"} {
		if err := os.Mkdir(filepath.Join(root, "wp-content/themes", d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mkfifo(t, filepath.Join(root, "wp-config.php"))
	mkfifo(t, filepath.Join(root, "auth.json"))
	mkfifo(t, filepath.Join(root, ".env"))
	if err := os.Symlink("/dev/zero", filepath.Join(root, "wp-content/themes/zero/style.css")); err != nil {
		t.Fatal(err)
	}
	// Unix socket paths are limited to about 100 bytes, less than a
	// macOS TMPDIR plus the tree needs, so bind in a short folder and
	// move the socket into the tree. If even that fails, only the
	// socket check is left out.
	sock := bindSocket(t, filepath.Join(root, "wp-content/themes/sock/style.css"))

	done := make(chan *engine.Result, 1)
	go func() {
		res, err := Scan(context.Background(), root, Options{Exec: fakePHP("8.3.6", nil)}, engine.Hooks{})
		if err != nil {
			t.Error(err)
		}
		done <- res
	}()
	var res *engine.Result
	select {
	case res = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scan blocked on a special file")
	}
	if res == nil {
		return
	}
	for _, want := range []string{
		"skipped /wp-config.php: it is a named pipe",
		"skipped /auth.json: it is a named pipe",
		"skipped /.env: it is a named pipe",
		"skipped /wp-content/themes/zero/style.css: it is a link to a character device",
	} {
		if !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.HasPrefix(w, want) }) {
			t.Errorf("no warning %q in %q", want, res.Warnings)
		}
	}
	if want := "skipped /wp-content/themes/sock/style.css: it is a socket"; sock && !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.HasPrefix(w, want) }) {
		t.Errorf("no warning %q in %q", want, res.Warnings)
	}
	if slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "couldn't read wp-config.php") }) {
		t.Errorf("wp-config.php warned twice: %q", res.Warnings)
	}
	// The regular theme next to them still counts.
	if !slices.ContainsFunc(res.Fingerprint.Components, func(c fingerprint.Component) bool { return c.Slug == "ok" }) {
		t.Errorf("components %+v", res.Fingerprint.Components)
	}
}

func TestReadHeadRefusesSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	mkfifo(t, fifo)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good")
	if err := os.Symlink(regular, good); err != nil {
		t.Fatal(err)
	}
	for path, kind := range map[string]string{fifo: "a named pipe", link: "a link to a named pipe", dir: "a folder", "/dev/null": "a character device"} {
		_, err := readHead(path, 10)
		var nr *notRegularError
		if !errors.As(err, &nr) || nr.kind != kind {
			t.Errorf("%s: err %v, want %s", path, err, kind)
		}
	}
	if b, err := readHead(good, 3); err != nil || string(b) != "hel" {
		t.Errorf("link to a regular file: %q %v", b, err)
	}
}

func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
}

// bindSocket puts a listening unix socket at path and reports whether it
// could. It binds under a short temporary folder (in TMPDIR, else /tmp)
// and renames the socket into place, since path itself may be over the
// socket path limit.
func bindSocket(t *testing.T, path string) bool {
	t.Helper()
	var err error
	for _, base := range []string{"", "/tmp"} {
		var dir string
		if dir, err = os.MkdirTemp(base, "s"); err != nil {
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		var ln net.Listener
		if ln, err = net.Listen("unix", filepath.Join(dir, "s")); err != nil {
			continue
		}
		t.Cleanup(func() { _ = ln.Close() })
		if err = os.Rename(filepath.Join(dir, "s"), path); err != nil {
			break // the socket is there but can't move; another folder won't help
		}
		return true
	}
	t.Logf("unix socket left out: %v", err)
	return false
}
