// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/update"
)

// checkForUpdate looks for a newer release while the scan runs, at most
// once a day. The channel yields the notice, or closes without one.
func checkForUpdate(ctx context.Context, ua string) <-chan string {
	notice := make(chan string, 1)
	go func() {
		u := &update.Updater{Repo: "RhythmShahriar/tuner", Binary: "rhythm-tuner", Current: version,
			UserAgent: ua, API: os.Getenv("RHYTHM_GITHUB_API")}
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if latest, newer := u.Check(cctx); newer {
			notice <- fmt.Sprintf("A new release of rhythm-tuner is available: %s → %s\n  run: rhythm update", version, latest)
		}
		close(notice)
	}()
	return notice
}

// printUpdateNotice prints the notice if the check has finished, waiting
// only briefly so a slow GitHub never holds up the exit.
func printUpdateNotice(notice <-chan string, stderr io.Writer) {
	select {
	case msg, ok := <-notice:
		if ok {
			fmt.Fprintln(stderr, msg)
		}
	case <-time.After(200 * time.Millisecond):
	}
}
