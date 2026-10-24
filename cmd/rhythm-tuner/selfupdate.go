// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/update"
)

// checkForUpdate looks for a newer release while the scan runs, at most
// once a day. The channel yields the notice, or closes without one. Offline
// runs (--offline or RHYTHM_OFFLINE) never ask GitHub.
func checkForUpdate(ctx context.Context, ua string, offline bool) <-chan string {
	notice := make(chan string, 1)
	if offline || envOn("RHYTHM_OFFLINE") {
		close(notice)
		return notice
	}
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

// envOn reports whether a switch variable is set to anything but empty,
// "0" or "false".
func envOn(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return v != "" && v != "0" && v != "false"
}
