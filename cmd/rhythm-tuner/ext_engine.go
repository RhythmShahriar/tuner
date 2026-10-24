// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"io"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/report"
)

// engineExtension adds the scan engine's safety flags to rhythm tuner scan.
// It has the scanExtension shape from extend.go; it is registered with
// registerScanExtension once that registry is in this tree.
type engineExtension struct {
	followHost    bool
	plugins       string
	requestBudget int
}

func (e *engineExtension) Help() string {
	return `Plugins:
      --plugins MODE       how hard to look for WordPress plugins the home
                           page does not load: passive (default) reads the
                           REST API index, one request; deep also checks
                           readme.txt of the 1,500 most installed plugins
      --request-budget N   most requests plugin discovery may send
                           (default 2000); the scan is partial if it runs out

Redirects:
      --follow-host        keep scanning when the site redirects to another
                           host; your -H headers and cookies still only go
                           to the host you named`
}

func (e *engineExtension) Flags(fs *flag.FlagSet) {
	fs.BoolVar(&e.followHost, "follow-host", false, "")
	fs.StringVar(&e.plugins, "plugins", "", "")
	fs.IntVar(&e.requestBudget, "request-budget", 0, "")
}

func (e *engineExtension) Plan(p *scanPlan) error {
	p.engine.FollowHost = e.followHost
	mode, err := engine.ParsePluginMode(e.plugins)
	if err != nil {
		return usageError{"--plugins: " + err.Error()}
	}
	p.engine.Plugins = mode
	if e.requestBudget < 0 {
		return usagef("--request-budget must be 0 or more, got %d", e.requestBudget)
	}
	p.engine.RequestBudget = e.requestBudget
	return nil
}

func (e *engineExtension) Finished(*scanPlan, []report.Report, io.Writer) (int, error) {
	return exitOK, nil
}
