// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"io"

	"github.com/RhythmShahriar/tuner/engine"
	"github.com/RhythmShahriar/tuner/report"
)

// init registers the engine flags with rhythm tuner scan.
func init() { registerScanExtension(&engineExtension{}) }

// engineExtension adds the scan engine's safety flags to rhythm tuner scan.
type engineExtension struct {
	followHost    bool
	plugins       string
	requestBudget int
}

// Help documents --plugins, --request-budget and --follow-host.
func (e *engineExtension) Help() string {
	return `Plugins:
      --plugins MODE       how hard to look for WordPress plugins the home
                           page does not load: passive (default) reads the
                           REST API index, one request; deep also checks
                           readme.txt of the 1,500 most installed plugins
      --request-budget N   most requests plugin discovery may send (default
                           2000); a budget you set makes the scan partial
                           when it runs out

Redirects:
      --follow-host        keep scanning when the site redirects to another
                           host; your -H headers and cookies still only go
                           to the host you named`
}

// Flags adds the engine flags.
func (e *engineExtension) Flags(fs *flag.FlagSet) {
	fs.BoolVar(&e.followHost, "follow-host", false, "")
	fs.StringVar(&e.plugins, "plugins", "", "")
	fs.IntVar(&e.requestBudget, "request-budget", 0, "")
}

// Plan passes the flags to the engine options, refusing bad values.
func (e *engineExtension) Plan(p *scanPlan) error {
	p.engine.FollowHost = e.followHost
	mode, err := engine.ParsePluginMode(e.plugins)
	if err != nil {
		return usagef("--plugins: %v", err)
	}
	p.engine.Plugins = mode
	if e.requestBudget < 0 {
		return usagef("--request-budget must be 0 or more, got %d", e.requestBudget)
	}
	p.engine.RequestBudget = e.requestBudget
	return nil
}

// Finished has nothing to add once the scan ends.
func (e *engineExtension) Finished(*scanPlan, []report.Report, io.Writer) (int, error) {
	return exitOK, nil
}
