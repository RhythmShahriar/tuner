// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/RhythmShahriar/tuner/engine"
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

func TestEngineExtensionPlugins(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		mode    engine.PluginMode
		budget  int
		wantErr string
	}{
		{nil, engine.PluginsPassive, 0, ""},
		{[]string{"--plugins", "deep", "--request-budget", "500"}, engine.PluginsDeep, 500, ""},
		{[]string{"--plugins", "DEEP"}, engine.PluginsDeep, 0, ""},
		{[]string{"--plugins", "loud"}, "", 0, `--plugins: unknown plugin discovery mode "loud": want passive or deep`},
		{[]string{"--request-budget", "-1"}, "", 0, "--request-budget must be 0 or more, got -1"},
	} {
		e := &engineExtension{}
		fs := flag.NewFlagSet("scan", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		e.Flags(fs)
		if err := fs.Parse(tc.args); err != nil {
			t.Fatal(err)
		}
		p := &scanPlan{}
		err := e.Plan(p)
		if tc.wantErr != "" {
			var ue usageError
			if !errors.As(err, &ue) || err.Error() != tc.wantErr {
				t.Errorf("%v: err %v, want usage error %q", tc.args, err, tc.wantErr)
			}
			continue
		}
		if err != nil || p.engine.Plugins != tc.mode || p.engine.RequestBudget != tc.budget {
			t.Errorf("%v: %q %d %v", tc.args, p.engine.Plugins, p.engine.RequestBudget, err)
		}
	}
	h := (&engineExtension{}).Help()
	for _, flag := range []string{"--plugins MODE", "--request-budget N"} {
		if !strings.Contains(h, flag) {
			t.Errorf("help lacks %s:\n%s", flag, h)
		}
	}
}

// The extension is registered, so scan parses its flags and lists them.
func TestEngineExtensionRegistered(t *testing.T) {
	p, err := planScan([]string{"example.com", "--follow-host", "--plugins", "deep", "--request-budget", "50"}, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if !p.engine.FollowHost || p.engine.Plugins != engine.PluginsDeep || p.engine.RequestBudget != 50 {
		t.Errorf("engine options %+v", p.engine)
	}
	if _, out, _ := tuner(t, "scan", "--help"); !strings.Contains(out, "--follow-host") || !strings.Contains(out, "--request-budget N") {
		t.Errorf("scan help lacks the engine flags:\n%s", out)
	}
}
