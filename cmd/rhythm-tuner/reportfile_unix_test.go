// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A new -o report gets the mode os.Create would give under the umask,
// so a umask of 077 keeps it private; a replaced one keeps its mode.
func TestReportHonorsUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	if got := readUmask(); got != 0o077 {
		t.Fatalf("readUmask %o", got)
	}
	defer func(m os.FileMode) { processUmask = m }(processUmask)
	processUmask = readUmask()

	path := filepath.Join(t.TempDir(), "new.json")
	if code, _, errs := tuner(t, "scan", leakySite(t).URL, "-o", path, "-q", "--no-vulns"); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("new report under umask 077: %v %v", fi.Mode(), err)
	}

	syscall.Umask(0o022)
	processUmask = readUmask()
	path = filepath.Join(t.TempDir(), "new.json")
	if code, _, errs := tuner(t, "scan", leakySite(t).URL, "-o", path, "-q", "--no-vulns"); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("new report under umask 022: %v %v", fi.Mode(), err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := tuner(t, "scan", leakySite(t).URL, "-o", path, "-q", "--no-vulns"); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o640 {
		t.Errorf("replaced report: %v %v", fi.Mode(), err)
	}
}

// -o refuses a link the kernel would refuse to follow: one another user
// planted in a sticky, world-writable folder such as /tmp.
func TestReportRefusesForeignLink(t *testing.T) {
	for _, c := range []struct {
		shared        bool
		link, dir, me uint32
		want          bool
	}{
		{false, 1001, 0, 1000, true},
		{true, 1000, 0, 1000, true},
		{true, 0, 0, 1000, true},
		{true, 1001, 0, 1000, false},
	} {
		if got := followAllowed(c.shared, c.link, c.dir, c.me); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}

	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(victim, []byte("ssh-ed25519 AAAA mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "report.md")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	defer func(f func(string, os.FileInfo) bool) { mayFollowLink = f }(mayFollowLink)
	mayFollowLink = func(string, os.FileInfo) bool { return false }
	code, _, errs := tuner(t, "scan", leakySite(t).URL, "-o", link, "-q", "--no-vulns")
	if code != exitError || !strings.Contains(errs, "can't write the report to "+link+": it is a symlink another user made in a shared folder") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if b, _ := os.ReadFile(victim); string(b) != "ssh-ed25519 AAAA mine\n" {
		t.Errorf("the link's target changed: %q", b)
	}

	// A real sticky, world-writable folder with our own link is fine.
	mayFollowLink = mayFollow
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(shared, "latest.json")
	target := filepath.Join(t.TempDir(), "real.json")
	if err := os.Symlink(target, own); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := tuner(t, "scan", leakySite(t).URL, "-o", own, "-q", "--no-vulns"); code != exitOK {
		t.Fatalf("own link in a shared folder: exit %d: %s", code, errs)
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("the report did not reach the link's target: %v", err)
	}
}
