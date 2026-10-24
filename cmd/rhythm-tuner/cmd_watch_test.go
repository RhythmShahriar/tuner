// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/tuner/watch"
)

// With fakeWatchEnv set, the test binary is a fake Tuner for the watch:
// it records its arguments in that file, writes the -o report and exits.
// This runs in init, before the testing package reads any flags.
const fakeWatchEnv = "TUNER_TEST_FAKE_WATCH_ARGV"

func init() {
	argv := os.Getenv(fakeWatchEnv)
	if argv == "" {
		return
	}
	args := os.Args[1:]
	b, _ := json.Marshal(args)
	_ = os.WriteFile(argv, append(b, '\n'), 0o600)
	if i := slices.Index(args, "-o"); i >= 0 {
		_ = os.WriteFile(args[i+1], []byte(`{"target":"https://example.com","findings":[{"id":"leak-dotenv","severity":"critical"}]}`), 0o600)
	}
	os.Exit(1) // a finding at --fail-on-new
}

func TestWatchOnce(t *testing.T) {
	dir := t.TempDir()
	argv := filepath.Join(dir, "argv.json")
	t.Setenv(fakeWatchEnv, argv)
	exe, _ := os.Executable()
	state := filepath.Join(dir, "state")
	var out, errb bytes.Buffer
	code := cmdWatch([]string{"example.com", "--once", "--exec", exe, "--dir", state,
		"--fail-on-new", "high", "--notify", "webhook+https://hooks.example/x", "--", "--profile", "quick"}, &out, &errb)
	if code != exitFindings {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errb.String())
	}
	b, _ := os.ReadFile(argv)
	var got []string
	json.Unmarshal(b, &got)
	list := filepath.Join(state, "sites.txt")
	if len(got) < 6 || got[5] == "" {
		t.Fatalf("argv %q", got)
	}
	want := []string{"scan", "-l", list, "--json", "-o", got[5],
		"--notify", "webhook+https://hooks.example/x", "--fail-on-new", "high", "--profile", "quick"}
	if !slices.Equal(got, want) {
		t.Errorf("argv\n%q\nwant\n%q", got, want)
	}
	if b, _ := os.ReadFile(list); string(b) != "example.com\n" {
		t.Errorf("sites.txt %q", b)
	}
	if !strings.Contains(out.String(), ": 1 site, 1 finding (1 critical); report "+got[5]+" (scan exit 1)") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestWatchFlags(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "Client Sites.txt")
	os.WriteFile(list, []byte("example.com\n"), 0o600)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))

	w, once, err := planWatch([]string{"-l", list, "--at", "02:00,14:30", "--now", "--keep", "5", "--html"})
	if err != nil || once {
		t.Fatal(err)
	}
	if w.List != list || !w.RunNow || w.Keep != 5 || !w.HTML || len(w.Schedule.At) != 2 {
		t.Errorf("%+v", w)
	}
	if cache, _ := os.UserCacheDir(); w.Dir != filepath.Join(cache, "rhythm", "tuner", "watch", "Client-Sites") {
		t.Errorf("dir %s", w.Dir)
	}
	if got := describeSchedule(w.Schedule); got != "daily at 02:00, 14:30" {
		t.Errorf("schedule %q", got)
	}
	for d, want := range map[time.Duration]string{24 * time.Hour: "every 24h", 90 * time.Minute: "every 1h30m", 90 * time.Second: "every 1m30s"} {
		if got := describeSchedule(watch.Schedule{Every: d}); got != want {
			t.Errorf("%s: %q", d, got)
		}
	}

	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-l", list}, "pick a schedule: --every <interval> or --at <HH:MM>"},
		{[]string{"-l", list, "--every", "10s"}, "--every 10s is too often; the shortest interval is 1m0s"},
		{[]string{"-l", list, "--every", "1h", "--at", "02:00"}, "pick one of --every and --at"},
		{[]string{"-l", list, "--at", "2am"}, `--at "2am": want a 24-hour time like 02:00`},
		{[]string{"-l", list, "--every", "1h", "--now"}, "--now goes with --at"},
		{[]string{"-l", list, "--once", "--every", "1h"}, "--once runs a single scan"},
		{[]string{"--every", "1h"}, "watch needs sites"},
		{[]string{"-l", list, "example.com", "--every", "1h"}, "pick one of -l <file> and sites"},
		{[]string{"-l", filepath.Join(dir, "missing.txt"), "--every", "1h"}, "can't read the site list"},
		{[]string{"./site", "--every", "1h"}, "watch scans sites by URL"},
		{[]string{"-l", list, "--every", "1h", "--fail-on-new", "severe"}, `--fail-on-new "severe": want one of`},
		{[]string{"-l", list, "--every", "1h", "--", "-o", "x.json"}, "the watch sets -o itself; drop it after --"},
		{[]string{"-l", list, "--every", "1h", "--", "--since=old.json"}, "the watch sets --since=old.json itself"},
		{[]string{"-l", list, "--every", "1h", "--keep", "-1"}, "--keep -1: want 0 or more"},
		{[]string{"-l", list, "--evrey", "1h"}, "unknown flag --evrey; did you mean --every?"},
	} {
		_, _, err := planWatch(c.args)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.args, err, c.want)
		}
	}

	var out, errb bytes.Buffer
	if code := cmdWatch([]string{"--help"}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "rhythm tuner watch -l <file> --every <interval>") {
		t.Errorf("help: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := cmdWatch([]string{"--every", "1h"}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "run 'rhythm tuner watch --help' for its flags") {
		t.Errorf("usage error: %d\n%s", code, errb.String())
	}
}
