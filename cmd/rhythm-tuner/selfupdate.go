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

	"github.com/RhythmShahriar/tuner/internal/release"
)

// releaseUpdater is the kit Updater for Tuner's own releases. offline
// (--offline) keeps it off the network; the kit adds RHYTHM_OFFLINE,
// RHYTHM_NO_UPDATE_CHECK and CI. It only looks up the latest tag: Tuner
// never installs a release itself (rhythm update does). A command that
// installs or locks one must set Verifier to release.NewVerifier, so the
// kit refuses a checksums.txt not signed for Tuner and that tag.
func releaseUpdater(ua string, offline bool) *update.Updater {
	return &update.Updater{
		Repo: release.Repo, Binary: release.Binary, Current: version, UserAgent: ua,
		API: os.Getenv("RHYTHM_GITHUB_API"), Offline: offline,
	}
}

// checkForUpdate looks for a newer release while the scan runs, at most
// once a day. The channel yields the notice, or closes without one.
// Offline runs (--offline or RHYTHM_OFFLINE) never ask GitHub.
func checkForUpdate(ctx context.Context, ua string, offline bool) <-chan string {
	return update.Notice(ctx, releaseUpdater(ua, offline))
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
