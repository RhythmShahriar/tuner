// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"io"
	"strings"
	"testing"
)

func TestEngineExtensionFollowHost(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"--follow-host"}, true},
	} {
		e := &engineExtension{}
		fs := flag.NewFlagSet("scan", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		e.Flags(fs)
		if err := fs.Parse(tc.args); err != nil {
			t.Fatal(err)
		}
		p := &scanPlan{}
		if err := e.Plan(p); err != nil {
			t.Fatal(err)
		}
		if p.engine.FollowHost != tc.want {
			t.Errorf("%v: FollowHost = %v", tc.args, p.engine.FollowHost)
		}
		if exit, err := e.Finished(p, nil, io.Discard); exit != exitOK || err != nil {
			t.Errorf("Finished = %d, %v", exit, err)
		}
	}
	if h := (&engineExtension{}).Help(); !strings.Contains(h, "--follow-host") {
		t.Errorf("help lacks the flag:\n%s", h)
	}
}
