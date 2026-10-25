// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"io"
	"os"

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
// once a day. It returns nil when there is nothing to check. Offline
// runs (--offline or RHYTHM_OFFLINE) never ask GitHub.
func checkForUpdate(ctx context.Context, ua string, offline bool) *update.Pending {
	return update.StartCheck(ctx, releaseUpdater(ua, offline))
}

// updatePrompt is what the scan hands update.PromptAtExit once its
// report is out. A machine format (--json, --jsonl, --sarif, --md) or -q
// never asks "Update now?", so a script reading the output never waits
// on an answer.
func updatePrompt(check *update.Pending, format string, quiet bool, stdout, stderr io.Writer) update.PromptOptions {
	return update.PromptOptions{Check: check, Quiet: quiet || format != "", Stdout: stdout, Out: stderr}
}
