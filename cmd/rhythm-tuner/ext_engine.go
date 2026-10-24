// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"io"

	"github.com/RhythmShahriar/tuner/report"
)

// engineExtension adds the scan engine's safety flags to rhythm tuner scan.
// It has the scanExtension shape from extend.go; it is registered with
// registerScanExtension once that registry is in this tree.
type engineExtension struct {
	followHost bool
}

func (e *engineExtension) Help() string {
	return `Redirects:
      --follow-host        keep scanning when the site redirects to another
                           host; your -H headers and cookies still only go
                           to the host you named`
}

func (e *engineExtension) Flags(fs *flag.FlagSet) {
	fs.BoolVar(&e.followHost, "follow-host", false, "")
}

func (e *engineExtension) Plan(p *scanPlan) error {
	p.engine.FollowHost = e.followHost
	return nil
}

func (e *engineExtension) Finished(*scanPlan, []report.Report, io.Writer) (int, error) {
	return exitOK, nil
}
