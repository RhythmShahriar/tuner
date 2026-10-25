// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/local"
)

func TestLocalExtensionIntegrity(t *testing.T) {
	t.Setenv("TUNER_WPORG_API", "http://127.0.0.1:20180")
	t.Setenv("TUNER_WPDL_API", "http://127.0.0.1:20181")
	e := &localExtension{}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	e.Flags(fs)
	if err := fs.Parse([]string{"--integrity"}); err != nil {
		t.Fatal(err)
	}
	var o local.Options
	proxy, _ := url.Parse("http://127.0.0.1:20182")
	e.configure(&o, "/srv/site", "tuner-test", proxy, true)
	c := o.Checksums
	if !o.Integrity || c == nil {
		t.Fatalf("options %+v", o)
	}
	if c.CoreBase != "http://127.0.0.1:20180" || c.PluginBase != "http://127.0.0.1:20181" || !c.Offline || c.UserAgent != "tuner-test" {
		t.Errorf("client %+v", c)
	}
	if c.CacheDir != "" && !strings.HasSuffix(c.CacheDir, "checksums") {
		t.Errorf("cache %q", c.CacheDir)
	}
	if !strings.Contains(e.Help(), "--integrity") {
		t.Error("help doesn't mention --integrity")
	}

	// Off by default: the options stay as they were.
	var off local.Options
	(&localExtension{}).configure(&off, "/srv/site", "ua", nil, false)
	if off.Integrity || off.Checksums != nil || off.SkipDirs != nil {
		t.Errorf("options %+v", off)
	}
}

func TestLocalExtensionDiscover(t *testing.T) {
	root := realTempDir(t)
	for _, f := range []string{"a/wp-includes/version.php", "a/wp-config.php", "a/blog/wp-includes/version.php", "a/blog/wp-config.php", "b/artisan"} {
		p := filepath.Join(root, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "b", "composer.json"), []byte(`{"require":{"laravel/framework":"^11"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &localExtension{}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	e.Flags(fs)
	if err := fs.Parse([]string{"--discover"}); err != nil {
		t.Fatal(err)
	}
	var w strings.Builder
	got, err := e.expand([]string{root, "example.com"}, &w)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(root, "a"), filepath.Join(root, "a", "blog"), filepath.Join(root, "b"), "example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("targets\n got %q\nwant %q", got, want)
	}
	if w.String() != "found 3 installs under "+root+"\n" {
		t.Errorf("message %q", w.String())
	}
	// The blog is its own target, so a's walk skips it.
	for target, skip := range map[string][]string{
		filepath.Join(root, "a"):         {filepath.Join(root, "a", "blog")},
		filepath.Join(root, "a", "blog"): nil,
		filepath.Join(root, "b"):         nil,
	} {
		var o local.Options
		e.configure(&o, target, "ua", nil, false)
		if !slices.Equal(o.SkipDirs, skip) {
			t.Errorf("%s skips %q, want %q", target, o.SkipDirs, skip)
		}
	}

	w.Reset()
	if got, _ := e.expand([]string{filepath.Join(root, "b")}, &w); len(got) != 1 || w.String() != "found 1 install under "+filepath.Join(root, "b")+"\n" {
		t.Errorf("one install: %q, %q", got, w.String())
	}

	// No installs, or no folder at all: usage errors.
	empty := realTempDir(t)
	var ue usageError
	if _, err := e.expand([]string{empty}, &w); !errors.As(err, &ue) || !strings.Contains(err.Error(), "found no WordPress or Laravel installs under "+empty) {
		t.Errorf("empty folder: %v", err)
	}
	if _, err := e.expand([]string{"example.com"}, &w); !errors.As(err, &ue) {
		t.Errorf("no folder: %v", err)
	}

	// Off: targets pass through.
	if got, _ := (&localExtension{}).expand([]string{empty}, &w); !slices.Equal(got, []string{empty}) {
		t.Errorf("off: %q", got)
	}
	if !strings.Contains(e.Help(), "--discover") {
		t.Error("help doesn't mention --discover")
	}
}

// Registered, --discover replaces the folder with its installs in the
// plan, says what it found before the scan and has each target's scan
// skip the installs nested in it.
func TestLocalExtensionPlan(t *testing.T) {
	root := realTempDir(t)
	for _, f := range []string{"a/wp-includes/version.php", "a/wp-config.php", "a/blog/wp-includes/version.php", "a/blog/wp-config.php"} {
		p := filepath.Join(root, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p, err := planScan([]string{root, "--discover", "--integrity", "--offline"}, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	a, blog := filepath.Join(root, "a"), filepath.Join(root, "a", "blog")
	if !slices.Equal(p.targets, []string{a, blog}) || !p.write.Many {
		t.Fatalf("targets %q, many %v", p.targets, p.write.Many)
	}
	if !slices.Contains(p.notes, "found 2 installs under "+root) {
		t.Errorf("notes %q", p.notes)
	}
	var o local.Options
	for _, f := range p.localFor {
		f(a, &o)
	}
	if !slices.Equal(o.SkipDirs, []string{blog}) || !o.Integrity || o.Checksums == nil || !o.Checksums.Offline {
		t.Errorf("options for %s: skip %q, integrity %v, checksums %+v", a, o.SkipDirs, o.Integrity, o.Checksums)
	}
}

// --integrity reads files: on URL targets alone it is a usage error like
// --discover. A mixed list says which targets go without it.
func TestIntegrityNeedsFolder(t *testing.T) {
	t.Setenv(invokedAsEnv, "rhythm tuner")
	var ue usageError
	_, err := planScan([]string{"https://example.com", "--integrity", "--no-config"}, strings.NewReader(""))
	if !errors.As(err, &ue) || ue.Msg != "--integrity needs a folder target, such as rhythm tuner scan --integrity /var/www/site" {
		t.Errorf("URL only: %v", err)
	}
	p, err := planScan([]string{t.TempDir(), "https://example.com", "--integrity", "--offline", "--no-config"}, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.notes, "--integrity checks folder targets only; 1 URL target is scanned without it") {
		t.Errorf("notes %q", p.notes)
	}
}
