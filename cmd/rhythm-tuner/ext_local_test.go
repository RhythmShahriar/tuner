// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"io"
	"net/url"
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
	e.configure(&o, "tuner-test", proxy, true)
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
	(&localExtension{}).configure(&off, "ua", nil, false)
	if off.Integrity || off.Checksums != nil {
		t.Errorf("options %+v", off)
	}
}
